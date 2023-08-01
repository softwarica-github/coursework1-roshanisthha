# Student ID:220084
# Student Name:Roshani Shrestha
# Module: ST5062CEM Programming and Algorithms 2
# Password Manager
import base64
import random
import string
import customtkinter as ct
from tkinter import messagebox
import pyperclip
import tkinter as tk
from PIL import Image, ImageTk
global encrypted_text

window = ct.CTk()
window.wm_iconbitmap('3.ico')
window.title("password manager")
window.geometry("600x340")

appearance_mode = 'dark'
def switch_mode():
    global appearance_mode
    if appearance_mode == 'dark':
        appearance_mode = 'light'
        ct.set_appearance_mode('light')
    else:
        appearance_mode = 'dark'
        ct.set_appearance_mode('dark')


def rot13_encode(text):
    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 65 + 13) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 97 + 13) % 26 + 97)
        else:
            result += char
    return result

def encryptData(data):
    rot_encrypted = rot13_encode(data)
    base64_encrypted = base64.b64encode(rot_encrypted.encode()).decode()
    return base64_encrypted


def rot13_decode(text):
    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 78) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 110) % 26 + 97)
        else:
            result += char
    return result

def data_decrypt(encrypted_text):
    base64_decrypted = base64.b64decode(encrypted_text).decode()
    rot_decrypted = rot13_decode(base64_decrypted)
    return rot_decrypted

def copy_to_clipboard(password):
    pyperclip.copy(password)
    messagebox.showinfo('Info', 'Password copied to clipboard!')


def gohome():
    Home_button = ct.CTkButton(  # if user need to go back
        window, text="Go to Home", command=first_window)
    Home_button.pack(pady=4)

def generate_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(8))
    return password

def getdetails():
    for widget in window.winfo_children():
        widget.destroy()
    sitename_label = ct.CTkLabel(window, text="Site Name:")
    sitename_label.pack(pady=10)

    sitename_entry = ct.CTkEntry(window)
    sitename_entry.pack()

    Username_label = ct.CTkLabel(window, text="Username:")
    Username_label.pack()

    Username_entry = ct.CTkEntry(window)
    Username_entry.pack()

    password_label = ct.CTkLabel(window, text="Password:")
    password_label.pack()

    password_entry = ct.CTkEntry(window, show="", )
    password_entry.pack()

    generate_btn = ct.CTkButton(window, text="Generate Password", command=lambda: password_entry.insert(
        "end", generate_password()),  fg_color="#17A589",
        hover_color="maroon",
        text_color="white")
    generate_btn.pack(pady=5)

    submit_button = ct.CTkButton(
        window, text="Submit", fg_color="#DE4249",
        hover_color="maroon",
        text_color="white", command=lambda: writedata(sitename_entry, Username_entry, password_entry)) 
    submit_button.pack()

    Home_button = ct.CTkButton(  
        window, text="Go to Home", command=first_window)
    Home_button.pack(pady=4) 



def writedata(sitename_entry, Username_entry, password_entry ):
    global encrypted_text

    site_check = sitename_entry.get()
    user_name = Username_entry.get()
    password = password_entry.get()

    if site_check != "" and user_name != "" and password != "":
        encrypted_text = f'{site_check},{user_name},{encryptData(password)}\n'
        with open("passwordinfo.txt", "a") as file:
            file.write(encrypted_text)

        for widget in window.winfo_children():
            widget.destroy()

        encrypted_label = ct.CTkLabel(
            window, text="The data you entered have been successfully encrypted and saved to passwordinfo.txt:")
        encrypted_label.pack(pady=15)

        encrypted_data_label = ct.CTkLabel(window, text=encrypted_text)
        encrypted_data_label.pack(pady=5)

        decrypt_btn = ct.CTkButton(
            window, text="Decrypt Data", fg_color="#DE4249",
            hover_color=("maroon"),
            text_color=("white"), command=create_decrypt_admin_pass)
        decrypt_btn.pack(pady=10)

        home_btn = ct.CTkButton(
            window, text="Take me Home", command=first_window)
        home_btn.pack(pady=10)

    else:
        messagebox.showerror('Error', "Entry fields cannot be empty!")



def create_decrypt_admin_pass():
    for widget in window.winfo_children():
        widget.destroy()
    admin_password = ct.CTkLabel(
        window, text="Enter a Admin Password that will help you to decrypted the file")
    admin_password.pack(pady=17)

    admin_password = ct.CTkLabel(window, text="Admin password:")
    admin_password.pack(pady=5)

    admin_password = ct.CTkEntry(window, show="*")
    admin_password.pack(pady=5)

    re_admin_password = ct.CTkLabel(window, text="Retype the admin password")
    re_admin_password.pack(pady=5)

    re_admin_password = ct.CTkEntry(window, show="*")
    re_admin_password.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit", fg_color="#DE4249",
                                 hover_color="maroon",
                                 text_color="white",
                                 command=lambda: passwordcheck(
                                     admin_password, re_admin_password)) 
    submit_button.pack(pady=4)



def passwordcheck(admin_password, re_admin_password):
    admin_pas = admin_password.get()
    re_admin_pas = re_admin_password.get()

    with open("adminpassword.txt", "r") as file:
        saved_admin_password = file.read().strip()

    if admin_pas == re_admin_pas and admin_pas == saved_admin_password:
        with open("adminpassword.txt", "w") as file:
            file.write(admin_pas)
        dec_final(admin_pas)
        messagebox.showinfo("Password Manager",
                            "Password has been saved successfully !!")
    else:
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()

def dec_final(admin_pas):
    global encrypted_text
    admin_password = admin_pas
    with open("adminpassword.txt", "r") as file:
        saved_password = file.read().strip()
    if saved_password == admin_password:
        try:
            decrypted_data = []
            contents = encrypted_text.split("\n")[:-1]
            for line in contents:
                site, user_id, password = line.strip().split(",")
                decrypted_password = data_decrypt(password)
                decrypted_data.append(
                    f"Site: {site}, User id: {user_id}, Password: {decrypted_password}")

            for widget in window.winfo_children():
                widget.destroy()

            for decrypted_line in decrypted_data:
                decrypted_label = ct.CTkLabel(window, text=decrypted_line)
                decrypted_label.pack(pady=15)

            home_btn = ct.CTkButton(
                window, text="Take me Home", hover_color="#DE4249", command=first_window)
            home_btn.pack(pady=15)

            picture_image = Image.open("2 (1).ico")
            picture_image = picture_image.resize((150, 150))
            picture_ctk_image = ImageTk.PhotoImage(picture_image)
            picture_label = tk.Label(window, image=picture_ctk_image)
            picture_label.image = picture_ctk_image
            picture_label.pack(pady=5)
            copy_btn = ct.CTkButton(window, text="Copy Password",
                                    fg_color="#DE4249",
                                    hover_color=("maroon"),
                                    text_color=("white"),
                                    command=lambda password=decrypted_password: copy_to_clipboard(password),)
            copy_btn.pack(pady=15)
        except Exception as e:
            print("Error:", e)
    else:
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()

def admin():
    for widget in window.winfo_children():
        widget.destroy()

    window.wm_iconbitmap('1.ico')
    window.title("password manager")
    admin_password = ct.CTkLabel(
        window, text="Enter the admin password you generated to decrypted the file")
    admin_password.pack(pady=20)

    admin_password = ct.CTkLabel(window, text="Admin Password:")
    admin_password.pack(pady=5)

    admin_password_entry = ct.CTkEntry(window, show="*")
    admin_password_entry.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit",  fg_color="#DE4249",
                                 hover_color="maroon",
                                 text_color="white",
                                 command=lambda: passcheck(admin_password_entry))
    submit_button.pack(pady=4)
    Home_button = ct.CTkButton(  # if user need to go back
        window, text="Go to Home", command=first_window)
    Home_button.pack(pady=4)

def passcheck(admin_password_entry):

    raw_pwd = admin_password_entry.get()

    with open("adminpassword.txt", "r") as file:
        raw_pw = file.read().strip()  
    if raw_pwd == raw_pw:  
        stored_info() 
    else:
        ct.CTkLabel(window, text="Error: Password do not match.").pack()

def stored_info(): 
    for widget in window.winfo_children(): 
        widget.destroy()

    msg_label = ct.CTkLabel(
        window, text="Successfully Entered !!")
    msg_label.pack(pady=5)

    website_label = ct.CTkLabel(
        window, text="Enter the site name you have saved: ")
    website_label.pack(pady=2)

    site_entry = ct.CTkEntry(window)
    site_entry.pack()

    username_label = ct.CTkLabel(
        window, text="Enter the user id you have saved: ")
    username_label.pack(pady=2)

    username_entry = ct.CTkEntry(window)
    username_entry.pack()

    submit_button = ct.CTkButton(
        window, text="Submit",  fg_color="#DE4249",
        hover_color="maroon",
        text_color="white",
        command=lambda: show(site_entry, username_entry)) 
    submit_button.pack(pady=4)

    Edit_button = ct.CTkButton(
        window, text="Edit password",
        fg_color="green",
        hover_color="maroon",
        text_color="white",
        command=lambda: edit(site_entry, username_entry))
    Edit_button.pack(pady=4)

    Home_button = ct.CTkButton( 
        window, text="Go to Home", command=first_window)
    Home_button.pack(pady=4)


def show(site_entry, username_entry):
    site_check = site_entry.get()
    user_check = username_entry.get()
    found = False
    with open("passwordinfo.txt", 'r') as f:
        contents = f.read().split("\n")[:-1]
        for line in contents:
            line_data = line.strip().split(",")
            if len(line_data) == 3:
                site, user_id, password = line_data
                decrypted_password = data_decrypt(password)
                if site == site_check and user_id == user_check:
                    found = True
                    msg_label = ct.CTkLabel(
                        window, text=f"Site: {site}, User: {user_id}, Password: {decrypted_password}", )
                    msg_label.pack()
                    copy_btn = ct.CTkButton(
                        window, text="Copy Password", command=lambda password=decrypted_password: copy_to_clipboard(password),)
                    copy_btn.pack(pady=5)
                    break

    if not found:
        msg_label = ct.CTkLabel(window, text="No data found for the site.")
        msg_label.pack()

def edit(site_entry, username_entry):
    site_check = site_entry.get()
    user_check = username_entry.get()
    data = []
    found = False
    with open("passwordinfo.txt", 'r') as f:
        contents = f.read().split("\n")[:-1]
        for line in contents:
            line_data = line.strip().split(",")
            if len(line_data) == 3:
                site, user_id, password = line_data
                decrypted_password = data_decrypt(password)
                temp = {
                    'Site': site,
                    'User id': user_id,
                    'Password': decrypted_password
                }
                data.append(temp)
    for item in data:
        if item['Site'] == site_check and item['User id'] == user_check:
            found = True

            for widget in window.winfo_children():
                widget.destroy()

            site_label = ct.CTkLabel(window, text="Site:")
            site_label.pack(pady=5)

            site_entry = ct.CTkEntry(window)
            site_entry.insert(0, item['Site'])
            site_entry.pack()

            username_label = ct.CTkLabel(window, text="Username:")
            username_label.pack(pady=2)

            username_entry = ct.CTkEntry(window)
            username_entry.insert(0, item['User id'])
            username_entry.pack()

            password_label = ct.CTkLabel(
                window, text="Enter the new password:")
            password_label.pack(pady=2)

            password_entry = ct.CTkEntry(window, show="*")
            password_entry.pack()

            generate_btn = ct.CTkButton(window, text="Generate Password", command=lambda: password_entry.insert(
                    "end", generate_password()),  fg_color="#17A589",
                    hover_color="maroon",
                    text_color="white")
            generate_btn.pack(pady=2)

            save_button = ct.CTkButton(
                window, text="Save Changes", 
                fg_color="#DE4249",hover_color="maroon",
                text_color="white", 
                command=lambda: save_changes(site_entry.get(), username_entry.get(), password_entry.get()))
            save_button.pack(pady=2)
            gohome()
    if not found:
        msg_label = ct.CTkLabel(
            window, text="No data found for the site.")
        msg_label.pack()

def save_changes(site_check, user_check, new_password):

    data = []
    with open("passwordinfo.txt", 'r') as f:
        contents = f.read().split("\n")[:-1]
        for line in contents:
            line_data = line.strip().split(",")
            if len(line_data) == 3:
                site, user_id, password = line_data
            decrypted_password = data_decrypt(password)
            temp = {
                'Site': site,
                'User id': user_id,
                'Password': decrypted_password
            }
            data.append(temp)
    for item in data:
        if item['Site'] == site_check and item['User id'] == user_check:
            item['Password'] = new_password

    with open("passwordinfo.txt", 'w') as f:
        for item in data:
            encrypted_password = encryptData(item['Password'])
            line = f"{item['Site']},{item['User id']},{encrypted_password}\n"
            f.write(line)

    msg_label = ct.CTkLabel(
        window, text="Changes saved successfully.")
    msg_label.pack()


def terminate():
    exit()

def first_window():
    for widget in window.winfo_children():
     widget.destroy()

    msg_label = ct.CTkLabel(
        window, text="हाम्रो पासवड म्यानेजर", font=("Arial", 25))
    msg_label.pack(pady=15)
    msg_label = ct.CTkLabel(
        window, text="अब सजिलै पासवड जेनेरेट र म्यानेज गर्नुहोस् !!", font=("Arial", 20))
    msg_label.pack()

    picture_image = Image.open("2 (1).ico")
    picture_image = picture_image.resize((70, 70))

    picture_ctk_image = ImageTk.PhotoImage(picture_image)

    picture_label = tk.Label(window, image=picture_ctk_image)
    picture_label.image = picture_ctk_image
    picture_label.pack(pady=5)

    new_label = ct.CTkButton(
        window, text="Create New Secure Passwords",
        command=getdetails,
        fg_color="#DE4249",
        hover_color="maroon",
        text_color="white")
    new_label.pack(pady=8)

    old_label = ct.CTkButton(
        window, text="View/Edit Old Passwords",
        command=admin,
        fg_color="#DE4249",
        hover_color="maroon",
        text_color="white")
    old_label.pack(pady=8)

    exit_btn = ct.CTkButton(
        window, text="Exit",
        command=terminate,
        fg_color="#DE4249",
        hover_color=("maroon"),
        text_color=("white"))
    exit_btn.pack(pady=5)

    switch = ct.CTkSwitch(window, text="Mode", command=switch_mode)
    switch.pack(pady=10)
first_window()

window.mainloop()
