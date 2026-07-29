
#include "cfe.h"

#include "ci_lab_app.h"
#include "ci_lab_perfids.h"
#include "ci_lab_msgids.h"
#include "ci_lab_decode.h"

#include "apqs_api.h"

/* -------------------------------------------------------------------------
 * MAP channel helpers
 * ------------------------------------------------------------------------- */

/**
 * Return the reassembly channel for map_id, or NULL if none is available.
 * A channel is "available" for a given map_id when it is either idle or
 * already tracking that map_id.
 */
static CI_LAB_ReassemblyState_t *CI_LAB_FindMapChannel(uint8_t map_id)
{
    int i;
    for (i = 0; i < CI_LAB_NUM_MAP_CHANNELS; i++)
    {
        if (!CI_LAB_Global.Reassembly[i].in_progress || CI_LAB_Global.Reassembly[i].map_id == map_id)
        {
            return &CI_LAB_Global.Reassembly[i];
        }
    }
    return NULL; /* all channels busy with a different MAP ID */
}

/** Reset a reassembly channel to idle. */
static void CI_LAB_ResetChannel(CI_LAB_ReassemblyState_t *ch)
{
    ch->in_progress = false;
    ch->offset      = 0;
}

/* -------------------------------------------------------------------------
 * Blocking: extract multiple SPs from a single PDU (seq_flags = 0b11)
 * ------------------------------------------------------------------------- */

/**
 * Walk the PDU interpreting it as concatenated CCSDS Space Packets.
 * Each SP is dispatched individually to the Software Bus.
 * Returns the number of SPs successfully dispatched.
 */
static int CI_LAB_ExtractBlockedSPs(const uint8_t *pdu, uint16_t pdu_len)
{
    int      count  = 0;
    uint16_t offset = 0;

    while (offset + 6 <= pdu_len) /* need at least 6 bytes for SP primary header */
    {
        /* CCSDS SP: Packet Data Length field (bytes 4-5) = total data field length - 1.
         * Total SP size = 6 (primary header) + Packet Data Length + 1 = 7 + field value. */
        uint16_t data_len = ((uint16_t)pdu[offset + 4] << 8) | (uint16_t)pdu[offset + 5];
        uint16_t sp_len   = (uint16_t)(7 + data_len);

        if ((uint32_t)offset + sp_len > pdu_len)
        {
            CFE_EVS_SendEvent(CI_LAB_SEG_BLOCKED_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: truncated SP in blocked PDU at offset %u (need %u, have %u)",
                              (unsigned)offset, (unsigned)sp_len, (unsigned)(pdu_len - offset));
            break;
        }

        CFE_SB_Buffer_t *sbBuf = CFE_SB_AllocateMessageBuffer(sp_len);
        if (sbBuf == NULL)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI_LAB: blocked SP buffer alloc failed at offset %u", (unsigned)offset);
            break;
        }

        memcpy(sbBuf, &pdu[offset], sp_len);
        CFE_SB_TransmitBuffer(sbBuf, false);
        CI_LAB_Global.HkTlm.Payload.IngestPackets++;
        count++;

        offset = (uint16_t)(offset + sp_len);
    }

    return count;
}

/* -------------------------------------------------------------------------
 * Segment handlers (called after Crypto_TC_ProcessSecurity)
 * The original network buffer has already been released by the caller
 * before these functions are invoked.
 * ------------------------------------------------------------------------- */

/**
 * seq_flags = 0b11 (Unsegmented / Blocked)
 *
 * If the PDU contains exactly one SP, return it via out_destBuff.
 * If it contains multiple SPs (blocking), dispatch them internally and
 * return CI_LAB_STATUS_DISPATCHED with *out_destBuff = NULL.
 */
static CFE_Status_t CI_LAB_HandleUnsegmented(const TC_t *tcBuff, uint8_t map_id,
                                              CFE_SB_Buffer_t **out_destBuff)
{
    int i;

    /* Discard any in-progress reassembly — an unsegmented frame resets state */
    for (i = 0; i < CI_LAB_NUM_MAP_CHANNELS; i++)
    {
        if (CI_LAB_Global.Reassembly[i].in_progress)
        {
            CFE_EVS_SendEvent(CI_LAB_SEG_ABORT_EID, CFE_EVS_EventType_INFORMATION,
                              "CI: unsegmented TC frame discards in-progress reassembly (MAP %u)",
                              (unsigned)CI_LAB_Global.Reassembly[i].map_id);
            CI_LAB_ResetChannel(&CI_LAB_Global.Reassembly[i]);
        }
    }

    if (tcBuff->tc_pdu_len < 7)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: unsegmented PDU too short (%u bytes)", (unsigned)tcBuff->tc_pdu_len);
        *out_destBuff = NULL;
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    /* Check whether the PDU contains exactly one SP or multiple (blocking) */
    uint16_t data_len  = ((uint16_t)tcBuff->tc_pdu[4] << 8) | (uint16_t)tcBuff->tc_pdu[5];
    uint16_t first_len = (uint16_t)(7 + data_len);

    if (first_len == tcBuff->tc_pdu_len)
    {
        /* Single SP — allocate SB buffer and return it */
        CFE_SB_Buffer_t *spacePacket = CFE_SB_AllocateMessageBuffer(tcBuff->tc_pdu_len);
        if (spacePacket == NULL)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI_LAB: unsegmented SP buffer alloc failed");
            *out_destBuff = NULL;
            return CFE_SB_BUF_ALOC_ERR;
        }
        memcpy(spacePacket, tcBuff->tc_pdu, tcBuff->tc_pdu_len);
        *out_destBuff = spacePacket;
        return CFE_SUCCESS;
    }
    else if (first_len < tcBuff->tc_pdu_len)
    {
        /* Blocked PDU: multiple SPs concatenated */
        CI_LAB_ExtractBlockedSPs(tcBuff->tc_pdu, tcBuff->tc_pdu_len);
        *out_destBuff = NULL;
        return CI_LAB_STATUS_DISPATCHED;
    }
    else
    {
        /* first_len > pdu_len: SP header claims more bytes than the PDU contains */
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: unsegmented PDU length mismatch: SP claims %u bytes, PDU is %u bytes",
                          (unsigned)first_len, (unsigned)tcBuff->tc_pdu_len);
        *out_destBuff = NULL;
        return CFE_STATUS_VALIDATION_FAILURE;
    }
}

/**
 * seq_flags = 0b01 (First segment)
 *
 * Start (or restart) a reassembly for the given MAP ID.
 * No SP is dispatched; *out_destBuff is set to NULL.
 */
static CFE_Status_t CI_LAB_HandleFirstSegment(const TC_t *tcBuff, uint8_t map_id,
                                               CFE_SB_Buffer_t **out_destBuff)
{
    *out_destBuff = NULL;

    CI_LAB_ReassemblyState_t *ch = CI_LAB_FindMapChannel(map_id);
    if (ch == NULL)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: no reassembly channel available for MAP %u", (unsigned)map_id);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    if (ch->in_progress)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_RESTART_EID, CFE_EVS_EventType_INFORMATION,
                          "CI: first segment received while reassembly active for MAP %u — discarding %u bytes",
                          (unsigned)map_id, (unsigned)ch->offset);
        CI_LAB_ResetChannel(ch);
    }

    if (tcBuff->tc_pdu_len > CI_LAB_MAX_REASSEMBLY_SIZE)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_OVERFLOW_EID, CFE_EVS_EventType_ERROR,
                          "CI: first segment PDU (%u bytes) exceeds reassembly buffer", (unsigned)tcBuff->tc_pdu_len);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    memcpy(ch->buffer, tcBuff->tc_pdu, tcBuff->tc_pdu_len);
    ch->offset      = tcBuff->tc_pdu_len;
    ch->in_progress = true;
    ch->map_id      = map_id;

    return CFE_SUCCESS;
}

/**
 * seq_flags = 0b00 (Continuation segment)
 *
 * Append PDU data to an active reassembly.
 * No SP is dispatched; *out_destBuff is set to NULL.
 */
static CFE_Status_t CI_LAB_HandleContinuation(const TC_t *tcBuff, uint8_t map_id,
                                               CFE_SB_Buffer_t **out_destBuff)
{
    *out_destBuff = NULL;

    CI_LAB_ReassemblyState_t *ch = CI_LAB_FindMapChannel(map_id);
    if (ch == NULL || !ch->in_progress)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_NO_FIRST_EID, CFE_EVS_EventType_ERROR,
                          "CI: continuation segment for MAP %u received with no active reassembly — discarding",
                          (unsigned)map_id);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    if (ch->map_id != map_id)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_MAPID_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: MAP ID mismatch — expected %u, got %u — discarding", (unsigned)ch->map_id,
                          (unsigned)map_id);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    if ((uint32_t)ch->offset + tcBuff->tc_pdu_len > CI_LAB_MAX_REASSEMBLY_SIZE)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_OVERFLOW_EID, CFE_EVS_EventType_ERROR,
                          "CI: reassembly overflow for MAP %u (%u + %u > %u) — discarding",
                          (unsigned)map_id, (unsigned)ch->offset, (unsigned)tcBuff->tc_pdu_len,
                          (unsigned)CI_LAB_MAX_REASSEMBLY_SIZE);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    memcpy(ch->buffer + ch->offset, tcBuff->tc_pdu, tcBuff->tc_pdu_len);
    ch->offset = (uint16_t)(ch->offset + tcBuff->tc_pdu_len);

    return CFE_SUCCESS;
}

/**
 * seq_flags = 0b10 (Last segment)
 *
 * Append the final PDU fragment, validate the reassembled SP, allocate an SB
 * buffer for the complete packet, and return it via out_destBuff.
 */
static CFE_Status_t CI_LAB_HandleLastSegment(const TC_t *tcBuff, uint8_t map_id,
                                              CFE_SB_Buffer_t **out_destBuff)
{
    *out_destBuff = NULL;

    CI_LAB_ReassemblyState_t *ch = CI_LAB_FindMapChannel(map_id);
    if (ch == NULL || !ch->in_progress)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_NO_FIRST_EID, CFE_EVS_EventType_ERROR,
                          "CI: last segment for MAP %u received with no active reassembly — discarding",
                          (unsigned)map_id);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    if (ch->map_id != map_id)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_MAPID_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: MAP ID mismatch on last segment — expected %u, got %u — discarding",
                          (unsigned)ch->map_id, (unsigned)map_id);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    if ((uint32_t)ch->offset + tcBuff->tc_pdu_len > CI_LAB_MAX_REASSEMBLY_SIZE)
    {
        CFE_EVS_SendEvent(CI_LAB_SEG_OVERFLOW_EID, CFE_EVS_EventType_ERROR,
                          "CI: reassembly overflow on last segment for MAP %u — discarding", (unsigned)map_id);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    /* Append final fragment */
    memcpy(ch->buffer + ch->offset, tcBuff->tc_pdu, tcBuff->tc_pdu_len);
    ch->offset = (uint16_t)(ch->offset + tcBuff->tc_pdu_len);

    uint16_t total = ch->offset;

    /* Validate the reassembled Space Packet */
    if (total < 7)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: reassembled SP for MAP %u too short (%u bytes)", (unsigned)map_id, (unsigned)total);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    uint16_t data_len   = ((uint16_t)ch->buffer[4] << 8) | (uint16_t)ch->buffer[5];
    uint16_t sp_claimed = (uint16_t)(7 + data_len);
    if (sp_claimed != total)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: reassembled SP length mismatch: header claims %u bytes, reassembled %u bytes",
                          (unsigned)sp_claimed, (unsigned)total);
        CI_LAB_ResetChannel(ch);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    /* Allocate SB buffer and copy the complete SP */
    CFE_SB_Buffer_t *spacePacket = CFE_SB_AllocateMessageBuffer(total);
    if (spacePacket == NULL)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI_LAB: reassembled SP buffer alloc failed (%u bytes)", (unsigned)total);
        CI_LAB_ResetChannel(ch);
        return CFE_SB_BUF_ALOC_ERR;
    }

    memcpy(spacePacket, ch->buffer, total);
    CI_LAB_ResetChannel(ch);

    CFE_EVS_SendEvent(CI_LAB_SEG_COMPLETE_EID, CFE_EVS_EventType_INFORMATION,
                      "CI: TC segment reassembly complete for MAP %u (%u bytes)", (unsigned)map_id, (unsigned)total);

    *out_destBuff = spacePacket;
    return CFE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

CFE_Status_t CI_LAB_GetInputBuffer(void **BufferOut, size_t *SizeOut)
{
    CFE_SB_Buffer_t *IngestBuffer;
    const size_t     IngestSize = CI_LAB_PLATFORM_MAX_INGEST;

    IngestBuffer = CFE_SB_AllocateMessageBuffer(IngestSize);
    if (IngestBuffer == NULL)
    {
        *BufferOut = NULL;
        *SizeOut   = 0;

        CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR, "CI_LAB: buffer allocation failed\n");

        return CFE_SB_BUF_ALOC_ERR;
    }

    *BufferOut = IngestBuffer;
    *SizeOut   = IngestSize;

    return CFE_SUCCESS;
}

/* CryptoLib extern: populated by Crypto_TC_ProcessSecurity for the frame just processed */
// TODO? why forward declared?
extern TCGvcidManagedParameters_t tc_current_managed_parameters_struct;

/* -------------------------------------------------------------------------
 * Build a TC_t from a clear (non-SDLS) CCSDS TC transfer frame.
 *
 * Frame shape comes from the CryptoLib managed parameters for the GVCID
 * (segment-header / FECF presence). Layout: [primary hdr 5][segment hdr 1?]
 * [PDU ...][FECF 2?]. The recovered PDU is copied into tcBuff->tc_pdu so the
 * normal dispatch/extraction helpers can run unchanged.
 * ------------------------------------------------------------------------- */
static CFE_Status_t CI_LAB_BuildClearTc(const uint8_t *frame, size_t frame_len, uint8_t tfvn, uint16_t scid,
                                        uint8_t vcid, TC_t *tcBuff, bool *has_seg_hdr_out)
{
    TCGvcidManagedParameters_t mp;

    if (apqs_Get_TC_Managed_Parameters_For_Gvcid(tfvn, scid, vcid,
        apqs_get_tc_gvcid_managed_parameters_array(), &mp) != CRYPTO_LIB_SUCCESS)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI_LAB: no managed params for clear GVCID scid=%u vcid=%u\n", (unsigned int)scid,
                          (unsigned int)vcid);
        return CFE_STATUS_VALIDATION_FAILURE;
    }

    bool   has_seg  = (mp.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS);
    size_t pdu_off  = TC_FRAME_HEADER_SIZE + (has_seg ? 1u : 0u);
    size_t fecf_len = (mp.has_fecf == TC_HAS_FECF) ? 2u : 0u;

    if (frame_len < pdu_off + fecf_len)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI_LAB: clear TC frame too short (%lu bytes)\n", (unsigned long)frame_len);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    size_t pdu_len = frame_len - pdu_off - fecf_len;
    if (pdu_len > TC_FRAME_DATA_SIZE)
    {
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI_LAB: clear TC PDU too large (%lu bytes)\n", (unsigned long)pdu_len);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    if (has_seg)
    {
        tcBuff->tc_sec_header.sh = frame[TC_FRAME_HEADER_SIZE];
    }

    memcpy(tcBuff->tc_pdu, &frame[pdu_off], pdu_len);
    tcBuff->tc_pdu_len = (uint16_t)pdu_len;

    *has_seg_hdr_out = has_seg;
    return CFE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Dispatch a populated TC_t (from CryptoLib or the clear path) to the Software
 * Bus: single space packet, blocked packets, or segmented reassembly. Owns the
 * release of the original network buffer (srcBuff).
 * ------------------------------------------------------------------------- */
static CFE_Status_t CI_LAB_DispatchTc(const TC_t *tcBuff, bool has_seg_hdr, void *srcBuff, size_t srcSize,
                                      CFE_SB_Buffer_t **out_destBuff)
{
    if (!has_seg_hdr)
    {
        /* ---- No segment header: single SP in PDU ---- */
        CFE_SB_Buffer_t *spacePacket = CFE_SB_AllocateMessageBuffer(tcBuff->tc_pdu_len);
        if (spacePacket == NULL)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI_LAB: crypto buffer allocation failed\n");
            CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
            return CFE_SB_BUF_ALOC_ERR;
        }

        memcpy(spacePacket, &tcBuff->tc_pdu[0], tcBuff->tc_pdu_len);

        CFE_MSG_Size_t msgSize;
        CFE_MSG_GetSize(&spacePacket->Msg, &msgSize);
        if (msgSize > srcSize)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: cmd dropped - length mismatch, %lu (hdr) / %lu (packet)\n",
                              (unsigned long)msgSize, (unsigned long)srcSize);
            CFE_SB_ReleaseMessageBuffer(spacePacket);
            CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
            return CFE_STATUS_WRONG_MSG_LENGTH;
        }

        CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);

        *out_destBuff = spacePacket;
        return CFE_SUCCESS;
    }
    else
    {
        /* ---- Segment header present: parse and handle reassembly / blocking ---- */
        uint8_t seg_hdr   = tcBuff->tc_sec_header.sh;
        uint8_t seq_flags = (seg_hdr >> 6) & 0x03;
        uint8_t map_id    = seg_hdr & 0x3F;

        /* The PDU data is already extracted into tcBuff; release the network buffer. */
        CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);

        switch (seq_flags)
        {
            case 0x03: /* Unsegmented / Blocked */
                return CI_LAB_HandleUnsegmented(tcBuff, map_id, out_destBuff);

            case 0x01: /* First segment */
                return CI_LAB_HandleFirstSegment(tcBuff, map_id, out_destBuff);

            case 0x00: /* Continuation segment */
                return CI_LAB_HandleContinuation(tcBuff, map_id, out_destBuff);

            case 0x02: /* Last segment */
                return CI_LAB_HandleLastSegment(tcBuff, map_id, out_destBuff);

            default:
                /* Unreachable: seq_flags is 2 bits */
                return CFE_STATUS_VALIDATION_FAILURE;
        }
    }
}

static void CI_LAB_ReStreamEpReply(void)
{
    uint8_t  ep_reply[TC_MAX_FRAME_SIZE];
    uint16_t ep_reply_len = 0;

    if (apqs_Get_Sdls_Ep_Reply(ep_reply, &ep_reply_len) == CRYPTO_LIB_SUCCESS && ep_reply_len >= 7)
    {
        uint16_t ccsds_len = ep_reply_len - 7;
        ep_reply[4]        = (ccsds_len >> 8) & 0xFF;
        ep_reply[5]        = ccsds_len & 0xFF;
        ep_reply[0]        = 0x08; /* version 0, TM, sec-hdr flag, APID[10:8]=0 */
        ep_reply[1]        = 0x7E; /* APID[7:0] = 0x7E -> APID 0x07E */

        CFE_SB_Buffer_t *replyBuf = CFE_SB_AllocateMessageBuffer(ep_reply_len);
        if (replyBuf != NULL)
        {
            memcpy(replyBuf, ep_reply, ep_reply_len);
            CFE_SB_TransmitBuffer(replyBuf, false);
        }
    }
}

CFE_Status_t CI_LAB_DecodeInputMessage(void *srcBuff, size_t srcSize, CFE_SB_Buffer_t **out_destBuff)
{
    uint8_t *ptr          = srcBuff;
    uint16_t spacecraftId = (((uint16_t)ptr[0] << 8) | ptr[1]) & 0x3FF;
    uint16_t frameLength  = (((uint16_t)ptr[2] << 8) | ptr[3]) & 0x3FF;

    if (spacecraftId == 3 && frameLength > 0)
    {
        /* ---- TC Transfer Frame path ---- */
        CFE_ES_WriteToSysLog("CI_LAB: Handling buffer as TC");

        // Trailing fill beyond the TC frame-length field (e.g. 0x55) must not be processed: clamp the working size to the frame length.
        if (srcSize > (size_t)(frameLength + 1))
        {
            srcSize = (size_t)(frameLength + 1);
        }

        *out_destBuff = NULL;

        /* GVCID determines whether this channel is SDLS-protected (route through
         * CryptoLib) or clear (parse the plain CCSDS frame directly). VCID is in the
         * TC primary header: byte 2, bits 7-2; TFVN is the top 2 bits of byte 0. */
        uint8_t tfvn = (ptr[0] >> 6) & 0x03;
        uint8_t vcid = (ptr[2] >> 2) & 0x3F;

        TC_t tcBuff;
        bool has_seg_hdr;
        memset(&tcBuff, 0x00, sizeof(tcBuff));

        if (TC_Gvcid_Has_Sdls(tfvn, spacecraftId, vcid))
        {
            /* ---- SDLS-protected GVCID: process through CryptoLib ---- */
            int32_t status = apqs_TC_ProcessSecurity(srcBuff, (int *)(&srcSize), &tcBuff);
            if (CRYPTO_LIB_SUCCESS != status)
            {
                CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                                  "CI Crypto: could not process TC errno = %i\n", status);
                return CFE_STATUS_VALIDATION_FAILURE;
            }

            /* tc_current_managed_parameters_struct is populated by Crypto_TC_ProcessSecurity. */
            has_seg_hdr = (tc_current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS);

            /* EP reply detected by the dedicated EP App ID (CRYPTOLIB_APPID = 384). */
            if ((((tcBuff.tc_pdu[0] & 0x07) << 8) | tcBuff.tc_pdu[1]) == CRYPTOLIB_APPID)
            {
                CI_LAB_ReStreamEpReply();
                CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
                *out_destBuff = NULL;
                return CFE_SUCCESS;
            }
        }
        else
        {
            /* ---- Clear (non-SDLS) GVCID: parse the plain CCSDS frame directly ---- */
            CFE_Status_t build_status =
                CI_LAB_BuildClearTc(ptr, srcSize, tfvn, spacecraftId, vcid, &tcBuff, &has_seg_hdr);
            if (build_status != CFE_SUCCESS)
            {
                CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
                return build_status;
            }

            // Detect SDLS EP by Cryptolib AppId
            if ((((tcBuff.tc_pdu[0] & 0x07) << 8) | tcBuff.tc_pdu[1]) == CRYPTOLIB_APPID)
            {
                int32_t ep_status = apqs_Process_Clear_TC_EP(ptr, (int)srcSize);
                if (ep_status != CRYPTO_LIB_SUCCESS)
                {
                    CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "CI Crypto: clear EP process failed errno=%i\n", (int)ep_status);
                    CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
                    return CFE_STATUS_VALIDATION_FAILURE;
                }
                CI_LAB_ReStreamEpReply();
                CFE_SB_ReleaseMessageBuffer((CFE_SB_Buffer_t *)srcBuff);
                *out_destBuff = NULL;
                return CFE_SUCCESS;
            }
        }

        return CI_LAB_DispatchTc(&tcBuff, has_seg_hdr, srcBuff, srcSize, out_destBuff);
    }
    else
    {
        /* ---- Space Packet path (passthrough): buffer ownership transferred to SB ---- */
        CFE_ES_WriteToSysLog("CI_LAB: Handling buffer as SP");

        CFE_SB_Buffer_t *MsgBufPtr;
        CFE_MSG_Size_t   MsgSize;
        CFE_Status_t     Status;

        if (srcSize < sizeof(CFE_MSG_CommandHeader_t))
        {
            MsgBufPtr = NULL;
            Status    = CFE_STATUS_WRONG_MSG_LENGTH;

            CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: cmd dropped, bad packet length=%lu\n", (unsigned long)srcSize);
        }
        else
        {
            MsgBufPtr = srcBuff;

            /* Check the size from within the header itself, compare against network buffer size */
            CFE_MSG_GetSize(&MsgBufPtr->Msg, &MsgSize);

            if (MsgSize > srcSize)
            {
                Status = CFE_STATUS_WRONG_MSG_LENGTH;

                CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                                  "CI: cmd dropped - length mismatch, %lu (hdr) / %lu (packet)\n",
                                  (unsigned long)MsgSize, (unsigned long)srcSize);
            }
            else
            {
                Status = CFE_SUCCESS;
            }
        }

        *out_destBuff = MsgBufPtr;

        return Status;
    }
}
