from collections import defaultdict
import easygui


start_key = """
A book cipher is a cipher in which each word or letter in the plaintext of a message is replaced by some code that locates it in another text, the key.

A simple version of such a cipher would use a specific book as the key, and would replace each word of the plaintext by a number that gives the position where that word occurs in that book. For example, if the chosen key is H. G. Wells's novel The War of the Worlds, the plaintext "all plans failed, coming back tomorrow" could be encoded as "335 219 881, 5600 853 9315" — since the 335th word of the novel is "all", the 219th is "plans", etc. This method requires that the sender and receiver use the exact same edition of the key book.

This simple version fails if the message uses a word that does not appear in the text. A variant that avoids this problem works with individual letters rather than words. Namely each letter of the plaintext message would be replaced by a number that specifies where that letter occurs in the key book. For example, using the same War of the Worlds book as the key, the message "no ammo" could be encoded as "12 10 / 50 31 59 34" since the words with those positions in the novel are "nineteenth", "of", "almost", "mortal", "might", and "own". This method was used in the second Beale cipher. This variant is more properly called a substitution cipher, specifically a homophonic one.

Both methods, as described, are quite laborious. Therefore, in practice, the key has usually been a codebook created for the purpose: a simple dictionary-like listing of all the words that might be needed to form a message, each with the respective code number(s). This version is called a code, and was extensively used from the 15th century up to World War II. 

The main strength of a book cipher is the key. The sender and receiver of encoded messages can agree to use any book or other publication available to both of them as the key to their cipher. Someone intercepting the message and attempting to decode it, unless they are a skilled cryptographer (see Security below), must somehow identify the key from a huge number of possibilities available. In the context of espionage, a book cipher has a considerable advantage for a spy in enemy territory. A conventional codebook, if discovered by the local authorities, instantly incriminates the holder as a spy and gives the authorities the chance of deciphering the code and sending false messages impersonating the agent. On the other hand, a book, if chosen carefully to fit with the spy's cover story, would seem entirely innocuous. The drawback to a book cipher is that both parties have to possess an identical copy of the key. The book must not be of the sort that would look out of place in the possession of those using it, and it must be of a type likely to contain any words required. Thus, a spy wishing to send information about troop movements and numbers of armaments would be unlikely to find a cookbook or romance novel useful keys. 

Another approach is to use a dictionary as the codebook. This guarantees that nearly all words will be found, and also makes it much easier to find a word when encoding. This approach was used by George Scovell for the Duke of Wellington's army in some campaigns of the Peninsular War. In Scovell's method, a codeword would consist of a number (indicating the page of the dictionary), a letter (indicating the column on the page), and finally a number indicating which entry of the column was meant. However, this approach also has a disadvantage: because entries are arranged in alphabetical order, so are the code numbers. This can give strong hints to the cryptanalyst unless the message is superenciphered. The wide distribution and availability of dictionaries also present a problem; it is likely that anyone trying to break such a code is also in possession of the dictionary which can be used to read the message. 

The Bible is a widely available book that is almost always printed with chapter and verse markings making it easy to find a specific string of text within it, making it particularly useful for this purpose; the widespread availability of concordances can ease the encoding process as well.

Essentially, the code version of a "book cipher" is just like any other code, but one in which the trouble of preparing and distributing the codebook has been eliminated by using an existing text. However this means, as well as being attacked by all the usual means employed against other codes or ciphers, partial solutions may help the cryptanalyst to guess other codewords, or even to break the code completely by identifying the key text. This is, however, not the only way a book cipher may be broken. It is still susceptible to other methods of cryptanalysis, and as such is quite easily broken, even without sophisticated means, without the cryptanalyst having any idea to what book the cipher is keyed.

If used carefully, the cipher version is probably much stronger, because it acts as a homophonic cipher with an extremely large number of equivalents. However, this is at the cost of a very large ciphertext expansion.

A famous use of a book cipher is in the Beale ciphers, of which Document No. 2 uses (a variant printing of) the United States Declaration of Independence as the key text.

In the American Revolution, Benedict Arnold used a book cipher, sometimes known as the Arnold Cipher, which used Sir William Blackstone's Commentaries on the Laws of England as a key text.

Book ciphers have consistently been used throughout the Cicada 3301 mystery.

https://en.wikipedia.org/wiki/Book_cipher
"""

start_msg = """
ENTER SECRETS HERE
"""

symbols_to_ignore = {
    '.', ',', '!', '?', ':', ';', '"', "'", '(', ')', '[', ']', '{', '}', 
    '-', '/', '\\', '&', '*', '#', '%', '$', '^', '_', '~', ' ', '\n'
}

def actual_encryption(key_message, UnencryptMsg):
    chars_to_nums = defaultdict(list)
    encryptedMsg = ""

    for i,st in enumerate(key_message):
        while len(st) > 0 and st[0] in symbols_to_ignore:
            st = st[1:]
        if len(st) > 0:
            chars_to_nums[st[0]].append(i+1)

    for c in UnencryptMsg:
        if  not c in symbols_to_ignore:
            if len(chars_to_nums[c]) > 0:
                encryptedMsg += str(chars_to_nums[c][0])+" "
                chars_to_nums[c].pop(0)
            else:
                encryptedMsg += '# '
    return encryptedMsg


def actual_decryption(key_message, EncryptMsg):
    output = ""
    for pair in EncryptMsg:
        output += key_message[int(pair)-1][0]
    return output


selection = easygui.buttonbox('                     Do you want to Encrypt or Decrypt?','Select Mode',['Encrypt','Encrypt from File','Decrypt','Decrypt from File'])
if selection == 'Encrypt':
    
    key_message = easygui.codebox('Enter Your Book Text', 'Enter Key',start_key)
    key_message = key_message.upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','').split(' ')

    UnencryptMsg = easygui.codebox('Enter Information to Encrypt', 'Enter Message',start_msg)
    UnencryptMsg = UnencryptMsg.upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','')
    
    encryptedMsg = actual_encryption(key_message, UnencryptMsg)
    easygui.msgbox('Encrypted Message: \n'+encryptedMsg, 'Encrypted Message')

elif selection == 'Encrypt from File':
    file_path_key = easygui.fileopenbox('Select a text file as the key')
    file_path_unencrypt = easygui.fileopenbox('Select a text file as the Message')
    message_key = ""
    message_unencr = ""
    with open(file_path_key, 'r') as file:
        message_key = file.read().upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','').split(' ')
    
    with open(file_path_unencrypt, 'r') as file:
        message_unencr = file.read().upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','')
    
    encryptedMsg = actual_encryption(message_key, message_unencr)
    easygui.msgbox('Encrypted Message: \n'+encryptedMsg, 'Encrypted Message')

elif selection == 'Decrypt from File':
    file_path_key = easygui.fileopenbox('Select a text file as the key')
    file_path_unencrypt = easygui.fileopenbox('Select a text file as the Encrypted Message')
    message_key = ""
    message_encr = ""
    with open(file_path_key, 'r') as file:
        message_key = file.read().upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','').split(' ')
    
    with open(file_path_unencrypt, 'r') as file:
        message_encr = file.read().upper().strip().replace('\n','').split(" ")
    
    encryptedMsg = actual_decryption(message_key, message_encr)
    easygui.msgbox('Decrypted Message: \n'+encryptedMsg, 'Decrypted Message')
else:
    
    key_message = easygui.codebox('Enter Your Book Text', 'Enter Key',start_key)
    key_message = key_message.upper().strip().replace('\n','').replace('.','').replace('?','').replace('!','').split(' ')

    EncryptMsg = easygui.codebox('Enter Information to Decrypt', 'Enter Encrypted Message',"9 56 14 49 20 22 69 3 48 94 24 32 75 116 119 127 ")
    EncryptMsg = EncryptMsg.upper().strip().replace('\n','').split(" ")

    
    UnencryptedMsg = actual_decryption(key_message, EncryptMsg)
    easygui.msgbox('Decrypted Message: \n'+UnencryptedMsg, 'Decrypted Message')
