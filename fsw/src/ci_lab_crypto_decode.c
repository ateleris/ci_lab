
#include "cfe.h"

#include "ci_lab_app.h"
#include "ci_lab_perfids.h"
#include "ci_lab_msgids.h"
#include "ci_lab_decode.h"

#include "crypto.h"

CFE_Status_t CI_LAB_GetInputBuffer(void **BufferOut, size_t *SizeOut)
{
    CFE_SB_Buffer_t *IngestBuffer;
    const size_t     IngestSize = CI_LAB_MAX_INGEST;

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

CFE_Status_t CI_LAB_DecodeInputMessage(void *srcBuff, size_t srcSize, CFE_SB_Buffer_t **out_destBuff)
{
    uint8_t *ptr = srcBuff;
    uint16_t spacecraftId = (((uint16_t)ptr[0] << 8) | ptr[1]) & 0x3FF;
    uint16_t frameLength  = (((uint16_t)ptr[2] << 8) | ptr[3]) & 0x3FF;
    if (spacecraftId == 3 && frameLength > 0)
    {
        // probably a TC
        CFE_ES_WriteToSysLog("CI_LAB: Handling buffer as TC");

        *out_destBuff = NULL;

        TC_t tcBuff;
        memset(&tcBuff, 0x00, sizeof(tcBuff));
        int32_t status = Crypto_TC_ProcessSecurity(srcBuff, (int *)(&srcSize), &tcBuff);
        if (CRYPTO_LIB_SUCCESS != status)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI Crypto: could not process TC errno = %i\n", status);

            return CFE_STATUS_VALIDATION_FAILURE;
        }

        CFE_SB_Buffer_t *spacePacket = CFE_SB_AllocateMessageBuffer(tcBuff.tc_pdu_len);
        if (spacePacket == NULL)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI_LAB: crypto buffer allocation failed\n");
            return CFE_SB_BUF_ALOC_ERR;
        }

        memcpy(spacePacket, &tcBuff.tc_pdu[0], tcBuff.tc_pdu_len);

        CFE_MSG_Size_t msgSize;
        CFE_MSG_GetSize(&spacePacket->Msg, &msgSize);
        if (msgSize > srcSize)
        {
            CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: cmd dropped - length mismatch, %lu (hdr) / %lu (packet)\n", (unsigned long)msgSize,
                              (unsigned long)srcSize);

            CFE_SB_ReleaseMessageBuffer(spacePacket);
            spacePacket = NULL;
            return CFE_STATUS_WRONG_MSG_LENGTH;
        }

        *out_destBuff = spacePacket;
        return CFE_SUCCESS;
    }
    else
    {
        // probably a SP
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
