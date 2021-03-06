/**
********************************************************************************************************
 * @file    test_atecc508a.c
 * @brief   Test suite for the ATECC508A on the Raspberry Pi w/ CryptoAuthXplained
 ********************************************************************************************************
 */


/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <ockam/define.h>
#include <ockam/error.h>

#include <ockam/vault.h>
#include <ockam/vault/tpm/microchip.h>

#include <cryptoauthlib/lib/cryptoauthlib.h>
#include <cryptoauthlib/lib/atca_cfgs.h>
#include <cryptoauthlib/lib/atca_iface.h>
#include <cryptoauthlib/lib/atca_device.h>

#include <test_vault.h>


/*
 ********************************************************************************************************
 *                                                DEFINES                                               *
 ********************************************************************************************************
 */

#define TEST_VAULT_ATECC508A_INIT_RETRY_COUNT       3u


/*
 ********************************************************************************************************
 *                                               CONSTANTS                                              *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                               DATA TYPES                                             *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                          FUNCTION PROTOTYPES                                         *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            GLOBAL VARIABLES                                          *
 ********************************************************************************************************
 */

ATCAIfaceCfg atca_iface_i2c = {
    .iface_type                 = ATCA_I2C_IFACE,
    .devtype                    = ATECC508A,
    {
        .atcai2c.slave_address  = 0xB0,
        .atcai2c.bus            = 1,
        .atcai2c.baud           = 100000,
    },
    .wake_delay                 = 1500,
    .rx_retries                 = 20
};

VAULT_MICROCHIP_CFG_s atecc508a_cfg = {
    .iface                      = VAULT_MICROCHIP_IFACE_I2C,
    .iface_cfg                  = &atca_iface_i2c,
};

OCKAM_VAULT_CFG_s vault_cfg =
{
    .p_tpm                       = &atecc508a_cfg,
    .p_host                      = 0,
    OCKAM_VAULT_EC_P256
};


/*
 ********************************************************************************************************
 *                                           GLOBAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            LOCAL FUNCTIONS                                           *
 ********************************************************************************************************
 */


/**
 ********************************************************************************************************
 *                                             main()
 *
 * @brief   Main point of entry for ATECC508A test
 ********************************************************************************************************
 */

void main (void)
{
    OCKAM_ERR err;
    uint8_t i;


    cmocka_set_message_output(CM_OUTPUT_XML);                   /* Configure the unit test output for JUnit XML       */

    /* ---------- */
    /* Vault Init */
    /* ---------- */

    for(i = 0; i < TEST_VAULT_ATECC508A_INIT_RETRY_COUNT; i++) {/* Initialize Vault. Retry if init fails. Failure may */
        err = ockam_vault_init((void*) &vault_cfg);             /* be due to wiring from the pi                       */
        if(err != OCKAM_ERR_NONE) {
            sleep(2);
        } else {
            break;
        }
    }

    if(err != OCKAM_ERR_NONE) {                                 /* Check if the init succeeded. If after a number of  */
        return;                                                 /* retries it still fails, just exit.                 */
    }

    /* ------------------------ */
    /* Random Number Generation */
    /* ------------------------ */

    test_vault_run_random();

    /* --------------------- */
    /* Key Generation & ECDH */
    /* --------------------- */

    test_vault_run_key_ecdh(vault_cfg.ec, 0);

    /* ------ */
    /* SHA256 */
    /* ------ */

    test_vault_run_sha256();

    /* -----*/
    /* HKDF */
    /* -----*/

    test_vault_run_hkdf();

    /* -------------------- */
    /* AES GCM Calculations */
    /* -------------------- */

    test_vault_run_aes_gcm();

    return;
}

