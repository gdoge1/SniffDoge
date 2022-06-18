rule CustomPayload
{
	meta:
		author = "Golden Doge"
		created_for = "SniffDoge"
		date = "6/18/2022"
		last_updated = "6/18/2022"

	strings:
		$type_custompayload_watermark = { 44 69 64 20 79 6F 75 20 6B 6E 6F 77 20 74 68 61 74 20 69 20 6D 61 64 65 20 74 68 69 73 21 20 43 75 73 74 6F 6D 50 61 79 6C 6F 61 64 23 31 33 33 37 }
		$type_custompayload_watermark_2 = { 64 6F 6E 74 20 66 75 63 6B 69 6E 67 20 72 65 6D 6F 76 65 20 74 68 65 20 77 61 74 65 72 6D 61 72 6B 2E 20 67 69 74 68 75 62 2E 63 6F 6D 2F 43 75 73 74 6F 6D 50 61 79 6C 6F 61 64 2F 53 6B 79 62 6C 6F 63 6B 2D 52 61 74 }
		$type_custompayload_custom_payload_watermark_3 = { 6F 68 20 77 61 69 74 20 69 20 6A 75 73 74 20 72 65 61 6C 69 73 65 64 20 61 6E 79 6F 6E 65 20 63 61 6E 20 65 61 73 69 6C 79 20 63 68 61 6E 67 65 20 74 68 69 73 20 6C 6F 6C 20 61 6E 64 20 74 68 65 6E 20 74 68 65 79 20 61 72 65 20 67 6F 6E 6E 61 20 62 65 20 74 68 69 6E 6B 69 6E 67 20 73 6F 6D 65 6F 6E 65 20 65 6C 73 65 20 6D 61 64 65 20 69 74 20 61 6E 64 20 69 74 20 77 69 6C 6C 20 73 75 63 6B 20 66 6F 72 20 74 68 65 20 72 65 61 6C 20 6F 77 6E 65 72 20 28 43 75 73 74 6F 6D 50 61 79 6C 6F 61 64 29 20 69 64 6B 20 68 65 20 63 61 6E 20 6A 75 73 74 20 65 61 73 69 6C 79 20 72 65 70 6C 61 63 65 20 74 68 69 73 20 62 75 74 20 79 65 61 20 74 68 61 74 20 68 61 70 70 65 6E 73 20 69 6D 20 67 6F 69 6E 67 20 74 6F 20 62 65 20 6E 75 6B 69 6E 67 20 65 76 65 72 79 6F 6E 65 73 20 77 65 62 68 6F 6F 6B 20 74 68 61 74 20 75 73 65 73 20 74 68 69 73 20 72 61 74 20 61 6E 64 20 63 68 61 6E 67 65 73 20 6D 79 20 77 61 74 65 72 6D 61 72 6B }
		$type_custompayload_pwned_request_cookie = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 37 34 2E 30 2E 33 37 32 39 2E 31 36 39 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
		$type_custompayload_pwned_request_url = { 68 74 74 70 73 3A 2F 2F 68 61 76 65 69 62 65 65 6E 70 77 6E 65 64 2E 63 6F 6D 2F 75 6E 69 66 69 65 64 73 65 61 72 63 68 2F }
		$type_custompayload_custom_is_not_einstein_lol = { 2F 2F 20 77 65 20 61 69 6E 74 20 73 6D 61 72 74 20 65 6E 6F 75 67 68 20 74 6F 20 64 6F 20 74 68 61 74 20 73 68 69 74 20 69 6E 20 6A 61 76 61 20 77 68 61 74 20 64 6F 20 69 20 6C 6F 6F 6B 20 6C 69 6B 65 20 66 75 63 6B 69 6E 67 20 65 69 6E 73 74 65 69 6E }

	condition:
		any of them
}

rule NeoRat
{
	meta:
		author = "Golden Doge"
		created_for = "SniffDoge"
		date = "6/18/2022"
		last_updated = "6/18/2022"

	strings:
		$type_neorat_heroku_url = { 68 65 72 6F 6B 75 61 70 70 2E 63 6F 6D }
		$type_neorat_session_func_b = { 66 75 6E 63 5F 31 31 31 32 38 36 5F 62 }
		$type_neorat_pizza_bypass = { 71 6F 6C 73 6B 79 62 6C 6F 63 6B 6D 6F 64 2E 70 69 7A 7A 61 63 6C 69 65 6E 74 2E 66 65 61 74 75 72 65 73 2E 6D 69 73 63 2E 53 65 73 73 69 6F 6E 50 72 6F 74 65 63 74 69 6F 6E }
	
	condition:
		any of them
}

rule Ben
{
	meta:
		author = "Golden Doge"
		created_for = "SniffDoge"
		date = "6/18/2022"
		last_updated = "6/18/2022"

	strings:
		$type_ben_get_ip = { 68 74 74 70 3A 2F 2F 63 68 65 63 6B 69 70 2E 61 6D 61 7A 6F 6E 61 77 73 2E 63 6F 6D }
		$type_ben_payment_sources = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 70 69 2F ?? ?? 2F 75 73 65 72 73 2F 40 6D 65 2F 62 69 6C 6C 69 6E 67 2F 70 61 79 6D 65 6E 74 2D 73 6F 75 72 63 65 73 }
		$type_ben_payment_sources_alt = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 2F ?? ?? 2F 75 73 65 72 73 2F 40 6D 65 2F 62 69 6C 6C 69 6E 67 2F 70 61 79 6D 65 6E 74 2D 73 6F 75 72 63 65 73 }
		$type_ben_discord_info = { 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 70 69 2F ?? ?? 2F 75 73 65 72 73 2F 40 6D 65 }
		$type_ben_cookie_stealing = { 5C 5C 47 6F 6F 67 6C 65 5C 5C 43 68 72 6F 6D 65 5C 5C 55 73 65 72 20 44 61 74 61 5C 5C 44 65 66 61 75 6C 74 5C 5C 4C 6F 67 69 6E 20 44 61 74 61 }

	condition:
		any of them
}