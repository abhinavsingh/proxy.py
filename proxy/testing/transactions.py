from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xf8658080831fc02094d01dfbe183f94628c0dd6c38593495a6f53618a380b844'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x8b3f8b9faa18784db9e46e65a4e623e40fb7eeb1'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
        'blockTime': 1656775953, 
        'meta': {
            'err': None, 
            'fee': 10000, 
            'innerInstructions': [
                {
                    'index': 2, 
                    'instructions': [ ### INNER INSTRUCTIONS OF CREATE ACCOUNT
                        {
                            'accounts': [
                                0,
                                1
                            ], 
                            'data': '111112gQz8Q2DLChCrULekEzng7cFTY6bAsdeXqpzowVNF3mgngXxd3xvEaqXNV92Dxr4w', 
                            'programIdIndex': 10
                        }
                    ]
                }, {
                    'index': 5, 
                    'instructions': [ ### INNER INSTRUCTIONS OF CLAIM
                        {
                            'accounts': [
                                0,
                                3
                            ], 
                            'data': '3Bxs4PckVVt51W8w', 
                            'programIdIndex': 10
                        },
                        {
                            'accounts': [
                                0,
                                9
                            ], 
                            'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL', 
                            'programIdIndex': 10
                        }, 
                        {
                            'accounts': [
                                9, #<== new token account
                                8, #<== mint account
                                7
                            ], 
                            'data': '5sK9aLfdJamhWLUum6kMzhf9Wah7k1ebSEmR2LaH7Xm9q', 
                            'programIdIndex': 6 ### TOKEN INITIALIZE ACCOUNT 2
                        },
                        {
                            'accounts': [
                                2,
                                9, #<== new ERC20 token account
                                1  #<== new Neon account
                            ], 
                            'data': '3QK1PgBtAWnb', 
                            'programIdIndex': 6 #### TOKEN TRANSFER
                        },
                        {
                            'accounts': [], 
                            'data': 'AHuintBcTxSXJiK7GKtMNd3GmRjcYrzngXR2xZtTW3dSfYkfPQH75Qfbxg7LWm2T1hXyzymhVReRWzfnoCAREDchLUyBVBvDw7S66P3aZgbmURjFzVTKmgZpN9hw4jMCStM6cnY9ZeJvT658RG61KzvAkSUnWzToziXuMnexf4VTScDWo7JqWM5unoUCbjnY1kBtpQEyVNpqdcQAtc1mrf', 
                            'programIdIndex': 13   ### EVM ON EVENT
                        },
                        {
                            'accounts': [], 
                            'data': '6sphUX89AzLs9pxG3HPWwWLrGsSqqZJEUgKaVZNraXkRdURmCDjtonqgc', 
                            'programIdIndex': 13 ### EVM ON RETURN
                        }
                    ]
                }
            ], 'logMessages': [
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]', 
                'Program log: Instruction: Create Account', 'Program 11111111111111111111111111111111 invoke [2]', 
                'Program 11111111111111111111111111111111 success', 
                'Program log: Total memory occupied: 488', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 7383 of 499944 compute units', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]', 
                'Program log: Instruction: Approve', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2377 of 492505 compute units', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]', 
                'Program log: Instruction: Execute Transaction from Instruction', 
                'Program 11111111111111111111111111111111 invoke [2]', 
                'Program 11111111111111111111111111111111 success', 
                'Program 11111111111111111111111111111111 invoke [2]', 
                'Program 11111111111111111111111111111111 success', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]', 
                'Program log: Instruction: InitializeAccount2', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3260 of 267498 compute units', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]', 
                'Program log: Instruction: Transfer', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3327 of 261232 compute units', 
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [2]', 
                'Program log: Total memory occupied: 0', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 716 of 256290 compute units', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success', 
                'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [2]', 
                'Program log: Total memory occupied: 0', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 718 of 252967 compute units', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success', 
                'Program log: Total memory occupied: 27168', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 239433 of 490072 compute units', 
                'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
            ], 'postBalances': [
                999996386680,
                1559040,
                2039280,
                905880,
                1559040,
                93048240,
                1090659840,
                1009200,
                1461600,
                2039280,
                1,
                1,
                0,
                8416588800,
                1
            ], 'postTokenBalances': [
                {
                    'accountIndex': 2, 
                    'mint': 'ExrSh69DBJWBgpjZrs6ZiiRhQGvL5WVJyfqEuovfzD24', 
                    'owner': 'Y9BTcpW2SV1Uv93TZiiQaNesMWbXEztibfRqGg8k5N7', 
                    'uiTokenAmount': {
                        'amount': '999999876544', 
                        'decimals': 9, 
                        'uiAmount': 999.999876544, 
                        'uiAmountString': '999.999876544'
                    }
                },
                {
                    'accountIndex': 9, 
                    'mint': 'ExrSh69DBJWBgpjZrs6ZiiRhQGvL5WVJyfqEuovfzD24', 
                    'owner': '7e5eQ3bht1uDDAP5TwXFc8KAanpa6KTvVx9pZqSqGXDR', 
                    'uiTokenAmount': {
                        'amount': '123456', 
                        'decimals': 9, 
                        'uiAmount': 0.000123456, 
                        'uiAmountString': '0.000123456'
                    }
                }
            ], 'preBalances': [
                1000000000000,
                0,
                2039280,
                900880,
                1559040,
                93048240,
                1090659840,
                1009200,
                1461600,
                0,
                1,
                1,
                0,
                8416588800,
                1
            ], 'preTokenBalances': [
                {
                    'accountIndex': 2, 
                    'mint': 'ExrSh69DBJWBgpjZrs6ZiiRhQGvL5WVJyfqEuovfzD24', 
                    'owner': 'Y9BTcpW2SV1Uv93TZiiQaNesMWbXEztibfRqGg8k5N7', 
                    'uiTokenAmount': {
                        'amount': '1000000000000', 
                        'decimals': 9, 
                        'uiAmount': 1000.0, 
                        'uiAmountString': '1000'
                    }
                }
            ], 'rewards': [], 'status': {'Ok': None
            }
        }, 
        'slot': 153, 
        'transaction': {
            'message': {
                'accountKeys': [
                    'Y9BTcpW2SV1Uv93TZiiQaNesMWbXEztibfRqGg8k5N7', 
                    '7cJRj15pmTTL3R29ppfJHAD9r2C9UWiKrSQMWwqFeJei',  #<== client Neon account (calculated from eth address 8b3f8b9faa18784db9e46e65a4e623e40fb7eeb1)
                    'A1Bhqq3NnsS4EnTbT69C3qVTna2PHvxBcbuHVU4wPSkd',  #<== source token account
                    'CmZQkRssybuGKNG1DfKKwH5cuC2EC75eYHrvTUeVWKNm', 
                    '7e5eQ3bht1uDDAP5TwXFc8KAanpa6KTvVx9pZqSqGXDR', 
                    'FiiMFtUdwWTz1sATw15MPLr7kixF48NJYczdQ59sqg1E', 
                    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 
                    'SysvarRent111111111111111111111111111111111', 
                    'ExrSh69DBJWBgpjZrs6ZiiRhQGvL5WVJyfqEuovfzD24', # <== Token Mint
                    'AEmaRAFVUUybHA3G2TuHFMydqVfwhr1mnSRbR38vYc2M', 
                    '11111111111111111111111111111111', 
                    'KeccakSecp256k11111111111111111111111111111', 
                    'Sysvar1nstructions1111111111111111111111111', 
                    '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io', 
                    'ComputeBudget111111111111111111111111111111'
                ], 
                'header': {
                    'numReadonlySignedAccounts': 0, 
                    'numReadonlyUnsignedAccounts': 5, 
                    'numRequiredSignatures': 1
                }, 
                'instructions': [
                    {
                        'accounts': [], 
                        'data': '16TYTJ8fLSxF', 
                        'programIdIndex': 14
                    },
                    {
                        'accounts': [], 
                        'data': '7YXqSw', 
                        'programIdIndex': 14
                    },
                    {
                        'accounts': [
                            0,
                            10,
                            1
                        ], 
                        'data': '7fNGdBmsEiyNqg1Jk5qWboqazW2EQW', 
                        'programIdIndex': 13 ### EVM CREATE ACCOUNT
                    },
                    {
                        'accounts': [
                            2,
                            1,
                            0
                        ], 
                        'data': '498XbEqWSBH1', 
                        'programIdIndex': 6   ### TOKEN APPROVE
                    },
                    {
                        'accounts': [
                            11
                        ], 
                        'data': '2CgVnE6omdn3yvxU', 
                        'programIdIndex': 11 ### KECCACK
                    },
                    {
                        'accounts': [
                            12,
                            0,
                            3,
                            1,
                            10,
                            13,
                            1,
                            4,
                            5,
                            6,
                            2,
                            7,
                            8,
                            9
                        ], 
                        'data': 'CZvrBbzQsA5BToTAyZMjpAxScCU43FyDTpifaWq3TT5J6Gxt7hBbiNTCmsaGuf2MsYwEjCnDcvQ5cmYeYGtdQyGXLymPmzHe3kEjZ5jDFgwyyEaZZnVTNjX2hbbsdWb3yF7hD52XY3BWrEeAN4a65KJYQp3wPsYoKJciqMw5oBxwhSwbyuR9MVgnQTB772SP16rwY7YQGGG1CjdERa95qwfiPQPpzbvP3vj26Wdc8tPehxWG67dG97jwNVSjj61VeaBLeSj', 
                        'programIdIndex': 13    #### NEON EVM CALL
                    }
                ], 
                'recentBlockhash': 'E4WGU3eEScAoPukWheMssYrhBDEDSVYLdFBtfoESjV9w'
            }, 
            'signatures': ['2BWFg9CgqWsxvXLVvGa3DsxdQaHTF7XL38PnKwjfvX1NZFgQW2gcL2htwMK84pwXDPMhRKQpGjV9ntdA4CBxKrLQ']
        }
    }
