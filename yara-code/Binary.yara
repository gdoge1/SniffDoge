rule bin
{
    meta:
        author = "Golden Doge"
        created_for = "SniffDoge"
        date = "6/17/2022"
        last_update = "this is first release lol"

    strings:
        $binhook = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 70 69 2F 77 65 62 68 6F 6F 6B 73 2F }
        $binhook_var = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 2F 77 65 62 68 6F 6F 6B 73 2F }
        $session_prot_byp = { 71 6F 6C 73 6B 79 62 6C 6F 63 6B 6D 6F 64 2E 70 69 7A 7A 61 63 6C 69 65 6E 74 2E 66 65 61 74 75 72 65 73 2E 6D 69 73 63 2E 53 65 73 73 69 6F 6E 50 72 6F 74 65 63 74 69 6F 6E }
        $guilded_webhook = { 6D 65 64 69 61 2E 67 75 69 6C 64 65 64 2E 67 67 }
        $heroku_url = { 68 65 72 6F 6B 75 61 70 70 2E 63 6F 6D } 
        $getting_discord_info = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 70 69 2F 76 36 2F 75 73 65 72 73 2F 40 6D 65 2F }
        $getting_discord_info_var = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 2F 76 36 2F 75 73 65 72 73 2F 40 6D 65 2F }
        $geting_payment_sorces = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 2F ?? ?? 2F 75 73 65 72 73 2F 40 6D 65 2F 62 69 6C 6C 69 6E 67 2F 70 61 79 6D 65 6E 74 2D 73 6F 75 72 63 65 73 }
        $getting_payment_sorces_var = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 2F ?? ?? 2F 75 73 65 72 73 2F 40 6D 65 2F 62 69 6C 6C 69 6E 67 2F 70 61 79 6D 65 6E 74 2D 73 6F 75 72 63 65 73 }
        $session_func_d = { 66 75 6E 63 5F 31 34 38 32 35 34 5F 64 }
        $session_func_b = { 66 75 6E 63 5F 31 31 31 32 38 36 5F 62 }
        $webhook_util = { 4A 61 76 61 2D 44 69 73 63 6F 72 64 57 65 62 68 6F 6F 6B 2D 42 59 2D 47 65 6C 6F 78 5F }
        $annonfiles_upload = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D 2F 75 70 6C 6F 61 64 }
        $branchlock_watermark = { 42 72 61 6E 63 68 6C 6F 63 6B 20 44 65 6D 6F }

    condition:
        any of them
}