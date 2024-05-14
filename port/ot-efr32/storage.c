/*******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * License: MSLA
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * Your use of this software is governed by the terms of Silicon Labs Master
 * Software License Agreement (MSLA) available at
 *
 * https://www.silabs.com/about-us/legal/master-software-license-agreement
 *
 * This software is distributed to you in Source Code format and is governed by
 * the sections of the MSLA applicable to Source Code.
 *
 * By installing, copying or otherwise using this software, you agree to the
 * terms of the MSLA.
 *
 ******************************************************************************/

#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_storage.h"

#include "nvm3_default.h"

/*
 * Silabs NVM3 keys use a 20-bit number where bits 19:16 are the stack region
 * bits 15:0 are available key IDss (0x0000 -> 0xFFFF).
 *
 * The KNX IoT reserved range is 0x89000 to 0x897FF. This range is further
 * broken down where the first 512 IDs (0x89000 to 0x891FF) are used for the
 * key name (i.e. "store" from the OC API) and the corresponding ID in the
 * 0x89400 to 0x895FF range is for the value. The 0x89200 to 0x893ff and
 * 0x89600 to 0x897ff ranges are not currently used.
 */
#define KNX_KEY_NAME_FIRST_NVM3_ID 0x89000U
#define KNX_KEY_NAME_LAST_NVM3_ID 0x891FFU
#define KNX_KEY_VALUE_FIRST_NVM3_ID 0x89400U
#define KNX_KEY_VALUE_LAST_NVM3_ID 0x895FFU
#define KNX_KEY_NVM3_VALUE_ID_OFFSET 0x00400U
#define KNX_MAX_KEY_NAME_NVM3_IDS (KNX_KEY_NAME_LAST_NVM3_ID - KNX_KEY_NAME_FIRST_NVM3_ID + 1)

_Static_assert(OC_STORAGE_MAX_FILES <= KNX_MAX_KEY_NAME_NVM3_IDS,
               "Max number of configure staorage files exceeds NVMS limit");

typedef struct oc_nvm3_key_pair_t
{
    nvm3_ObjectKey_t nameKey;
    nvm3_ObjectKey_t valueKey;
} oc_nvm3_key_pair_t;

static bool nvmOpenedByKNX = false;

#define ENUM_NVM3_KEY_LIST_SIZE 32

/**
 * @brief Check the given set of keys to see if the nvm3 object asscoiated with them matches the given "store" (aka
 * filename)
 *
 * @param store the filename to match
 * @param storeLen the string length of "store"
 * @param keys the list of keys to check
 * @param numKeys the number of keys in the "keys" array
 * @return the matching nvm3 key or NVM3_KEY_INVALID if no match is found
 */
static nvm3_ObjectKey_t oc_search_nvm3_keys(const char *store, size_t storeLen, nvm3_ObjectKey_t *keys, size_t numKeys)
{
    nvm3_ObjectKey_t nvm3Key = NVM3_KEY_INVALID;
    Ecode_t          error   = ECODE_NVM3_OK;

    for (size_t i = 0; i < numKeys; ++i)
    {
        uint32_t objType;
        size_t   objLen;
        char     keyName[OC_STORAGE_MAX_FILENAME_LENGTH];

        oc_success_or_exit(error = nvm3_getObjectInfo(nvm3_defaultHandle, keys[i], &objType, &objLen));
        // We should never have written a key name longer than OC_STORAGE_MAX_FILENAME_LENGTH.
        // Note: that the null terminator character at the end of key name is not stored in NVM.
        oc_assert(objLen <= OC_STORAGE_MAX_FILENAME_LENGTH);
        // Continue searching if the stored object length does not match the length of the given filename
        if (storeLen != objLen)
            continue;
        oc_success_or_exit(error = nvm3_readData(nvm3_defaultHandle, keys[i], keyName, objLen));
        // Continue searching if the given name does not match the stored name
        oc_verify_or_exit((strncmp(store, keyName, storeLen) != 0), nvm3Key = keys[i]);
    }

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_search_nvm3_keys: NVM3 error 0x%08X", error);
        return NVM3_KEY_INVALID;
    }

    return nvm3Key;
}

/**
 * @brief Lookup the key pair for the given "store" (aka filename)
 *
 * @param store the filename to match
 * @param nvm3KeyPair pointer to the location where the key pair will be returned
 * @return True if the key pair found, false otherwise
 */
static bool oc_lookup_nvm3_key_pair(const char *store, oc_nvm3_key_pair_t *nvm3KeyPair)
{
    bool             nameFound = false;
    Ecode_t          error     = ECODE_NVM3_OK;
    size_t           objCnt;
    size_t           storeLen = strlen(store);
    nvm3_ObjectKey_t keys[ENUM_NVM3_KEY_LIST_SIZE];

    nvm3KeyPair->nameKey  = NVM3_KEY_INVALID;
    nvm3KeyPair->valueKey = NVM3_KEY_INVALID;

    OC_DBG("oc_lookup_nvm3_key_pair: %s", store);

    // Obtain the number of currently stored key names.  If the number is less than or equal to ENUM_NVM3_KEY_LIST_SIZE
    // then we only need to call nvm3_enumObjects once.  If the number is greater than ENUM_NVM3_KEY_LIST_SIZE then
    // we'll need to loop through all objects in chunks of ENUM_NVM3_KEY_LIST_SIZE.
    objCnt = nvm3_enumObjects(nvm3_defaultHandle, NULL, 0, KNX_KEY_NAME_FIRST_NVM3_ID, KNX_KEY_NAME_LAST_NVM3_ID);

    // If there are no objects currently stored we are done
    oc_verify_or_exit(objCnt > 0, nameFound = false);

    if (objCnt <= ENUM_NVM3_KEY_LIST_SIZE)
    {
        objCnt               = nvm3_enumObjects(nvm3_defaultHandle,
                                  keys,
                                  ENUM_NVM3_KEY_LIST_SIZE,
                                  KNX_KEY_NAME_FIRST_NVM3_ID,
                                  KNX_KEY_NAME_LAST_NVM3_ID);
        nvm3KeyPair->nameKey = oc_search_nvm3_keys(store, storeLen, keys, objCnt);
        nameFound            = (nvm3KeyPair->nameKey != NVM3_KEY_INVALID);
    }
    else
    {
        nvm3_ObjectKey_t rangeStart = KNX_KEY_NAME_FIRST_NVM3_ID;
        while (rangeStart <= KNX_KEY_NAME_LAST_NVM3_ID && !nameFound)
        {
            nvm3_ObjectKey_t rangeEnd = rangeStart + ENUM_NVM3_KEY_LIST_SIZE - 1;
            rangeEnd                  = (rangeEnd <= KNX_KEY_NAME_LAST_NVM3_ID) ? rangeEnd : KNX_KEY_NAME_LAST_NVM3_ID;
            objCnt = nvm3_enumObjects(nvm3_defaultHandle, keys, ENUM_NVM3_KEY_LIST_SIZE, rangeStart, rangeEnd);
            if (objCnt > 0)
            {
                nvm3KeyPair->nameKey = oc_search_nvm3_keys(store, storeLen, keys, objCnt);
                nameFound            = (nvm3KeyPair->nameKey != NVM3_KEY_INVALID);
            }
            rangeStart = rangeEnd + 1;
        }
    }

    nvm3KeyPair->valueKey = (nameFound) ? nvm3KeyPair->nameKey + KNX_KEY_NVM3_VALUE_ID_OFFSET : NVM3_KEY_INVALID;

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_lookup_nvm3_key_pair: NVM3 error 0x%08X", error);
        return false;
    }

    OC_DBG("oc_lookup_nvm3_key_pair: returning name=0x%08X, value=0x%08X", nvm3KeyPair->nameKey, nvm3KeyPair->valueKey);
    return nameFound;
}

/**
 * @brief Find and available slot in NVM
 *
 * @param nvm3KeyPair pointer to the location where the available key pair will be returned
 * @return True if an available slot was found, false otherwise
 */
static bool oc_find_avaliable_nvm3_key_pair(oc_nvm3_key_pair_t *nvm3KeyPair)
{
    nvm3_ObjectKey_t nvm3Key;
    Ecode_t          error = ECODE_NVM3_OK;

    nvm3KeyPair->nameKey  = NVM3_KEY_INVALID;
    nvm3KeyPair->valueKey = NVM3_KEY_INVALID;

    for (nvm3Key = KNX_KEY_NAME_FIRST_NVM3_ID; nvm3Key <= KNX_KEY_NAME_LAST_NVM3_ID; ++nvm3Key)
    {
        uint32_t objType;
        size_t   objLen;
        // We'll continue looping as long as we keep finding objects.  As soon as there's a failure,
        // which includes ECODE_NVM3_ERR_KEY_NOT_FOUND, we'll exit.
        oc_success_or_exit(error = nvm3_getObjectInfo(nvm3_defaultHandle, nvm3Key, &objType, &objLen));
    }

    error = ECODE_NVM3_ERR_STORAGE_FULL;

exit:
    if (error == ECODE_NVM3_ERR_KEY_NOT_FOUND)
    {
        nvm3KeyPair->nameKey  = nvm3Key;
        nvm3KeyPair->valueKey = nvm3Key + KNX_KEY_NVM3_VALUE_ID_OFFSET;
    }
    else if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_find_avaliable_nvm3_key_pair: NVM3 error 0x%08X", error);
        return false;
    }

    OC_DBG("oc_find_avaliable_nvm3_key_pair: returning name=0x%08X, value=0x%08X",
           nvm3KeyPair->nameKey,
           nvm3KeyPair->valueKey);
    return true;
}

int oc_storage_config(const char *store)
{
    Ecode_t error = ECODE_NVM3_OK;

    // We don't set up separate NVM3 regions for the config "store" because
    // one application will have one config "store" and if another application is
    // loaded its NVM3 storage will replace the previous "store".  It's not like a
    // a windows or linux system where you may run multiple applications and you
    // need to seperate the config stores for each application.

    OC_DBG("Initializing storage: %s", store);

    oc_verify_or_exit(!nvm3_defaultHandle->hasBeenOpened, error = ECODE_NVM3_OK);
    oc_success_or_exit(error = nvm3_open(nvm3_defaultHandle, nvm3_defaultInit));

    // There is no OC API to unitialize the storage but if there was we would
    // check nvmOpenedByKNX and only call nvm3_close if true.
    nvmOpenedByKNX = true;

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_storage_config: NVM3 error 0x%08X", error);
        return -1;
    }

    return 0;
}

long oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
    long               bytesRead = 0;
    oc_nvm3_key_pair_t nvm3KeyPair;
    Ecode_t            error = ECODE_NVM3_OK;
    size_t             readLen;

    if (oc_lookup_nvm3_key_pair(store, &nvm3KeyPair))
    {
        uint32_t objType;
        size_t   objLen;
        oc_success_or_exit(error = nvm3_getObjectInfo(nvm3_defaultHandle, nvm3KeyPair.valueKey, &objType, &objLen));
        readLen = (objLen > size) ? size : objLen;
        oc_success_or_exit(error = nvm3_readData(nvm3_defaultHandle, nvm3KeyPair.valueKey, buf, readLen));
        bytesRead = readLen;
    }

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_storage_read: NVM3 error 0x%08X", error);
        bytesRead = 0;
    }

    OC_DBG("oc_storage_read: returning %u for %s", bytesRead, store);
    return bytesRead;
}

long oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
    long               bytesWritten = 0;
    size_t             storeLen     = strlen(store);
    oc_nvm3_key_pair_t nvm3KeyPair;
    Ecode_t            error = ECODE_NVM3_OK;

    oc_assert(storeLen <= OC_STORAGE_MAX_FILENAME_LENGTH);

    if (oc_lookup_nvm3_key_pair(store, &nvm3KeyPair))
    {
        uint32_t objType;
        size_t   objLen;
        // key already exists, ensure that the size of the stored value is
        // the same as the size to be written. If not we'll need to delete the
        // previous value.
        oc_success_or_exit(error = nvm3_getObjectInfo(nvm3_defaultHandle, nvm3KeyPair.valueKey, &objType, &objLen));
        if (size != objLen)
        {
            oc_success_or_exit(error = nvm3_deleteObject(nvm3_defaultHandle, nvm3KeyPair.valueKey));
        }
    }
    else
    {
        // Find an avaliable slot and store the key name. Note that the null terminator is not stored
        oc_verify_or_exit(oc_find_avaliable_nvm3_key_pair(&nvm3KeyPair), error = ECODE_NVM3_ERR_STORAGE_FULL);
        oc_success_or_exit(error = nvm3_writeData(nvm3_defaultHandle, nvm3KeyPair.nameKey, store, storeLen));
    }

    oc_success_or_exit(error = nvm3_writeData(nvm3_defaultHandle, nvm3KeyPair.valueKey, buf, size));
    bytesWritten = size;

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_storage_write: NVM3 error 0x%08X", error);
        return 0;
    }

    OC_DBG("oc_storage_write: returning %u for %s", bytesWritten, store);
    return bytesWritten;
}

int oc_storage_erase(const char *store)
{
    oc_nvm3_key_pair_t nvm3KeyPair;
    Ecode_t            error = ECODE_NVM3_OK;

    oc_verify_or_exit(oc_lookup_nvm3_key_pair(store, &nvm3KeyPair), error = ECODE_NVM3_ERR_KEY_NOT_FOUND);
    oc_success_or_exit(error = nvm3_deleteObject(nvm3_defaultHandle, nvm3KeyPair.nameKey));
    oc_success_or_exit(error = nvm3_deleteObject(nvm3_defaultHandle, nvm3KeyPair.valueKey));

exit:
    if (error != ECODE_NVM3_OK)
    {
        OC_ERR("oc_storage_erase: NVM3 error 0x%08X", error);
        return -1;
    }

    OC_DBG("oc_storage_erase: returning 0 for %s", store);
    return 0;
}
