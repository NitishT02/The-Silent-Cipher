from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from stegano import lsb
import os

# Global variables for credentials
credentials_file = "credentials.txt"  # Path to store credentials
admin_user = "admin"  # Define the admin username

# Declare current_user as a global variable to be used across functions
current_user = None

# Function to read stored credentials from the text file, including the secret key
def read_credentials():
    if os.path.exists(credentials_file):
        with open(credentials_file, 'r') as file:
            data = file.readlines()
        credentials = {}
        for line in data:
            line = line.strip()
            if ':' in line:  # Only process valid lines with 'username:password:secret_key'
                username, password, secret_key = line.split(':')
                credentials[username] = (password, secret_key)  # Store password and secret key
        return credentials
    return {}

# Function to save new credentials in the text file, including the secret key
def save_credentials(username, password, secret_key):
    with open(credentials_file, 'a') as file:
        file.write(f"{username}:{password}:{secret_key}\n")

# Function to handle login validation
def login():
    global current_user, current_secret_key  # Declare current_secret_key
    username = login_username.get()
    password = login_password.get()

    # Read the credentials from the file
    credentials = read_credentials()

    if username in credentials:
        stored_password, stored_secret_key = credentials[username]
        if stored_password == password:
            current_user = username  # Set the current user
            current_secret_key = stored_secret_key  # Store the secret key
            if current_user == admin_user:
                messagebox.showinfo("Login Success", "Welcome Admin!")
            else:
                messagebox.showinfo("Login Success", "Welcome User!")
            login_window.destroy()  # Close login window on success
            main_app()  # Proceed to the main app
        else:
            messagebox.showerror("Login Failed", "Invalid credentials.")
    else:
        messagebox.showerror("Login Failed", "Invalid credentials.")

# Function to handle user signup
def signup():
    username = signup_username.get()
    password = signup_password.get()
    confirm_password = signup_confirm_password.get()
    secret_key = signup_secret_key.get()  # Get the secret key from the entry field

    if password == confirm_password:
        credentials = read_credentials()

        if username in credentials:
            messagebox.showerror("Signup Error", "User already exists!")
        else:
            save_credentials(username, password, secret_key)  # Save username, password, and secret key
            messagebox.showinfo("Signup Success", "Account created successfully! Please login.")
            signup_window.destroy()
            login_page()  # Redirect to login page after signup
    else:
        messagebox.showerror("Signup Error", "Passwords do not match!")

# Login window
def login_page():
    global login_window, login_username, login_password
    login_window = Tk()
    login_window.title("Login")
    login_window.geometry("400x300")
    login_window.resizable(False, False)

    Label(login_window, text="Login", font="Arial 18 bold").pack(pady=20)

    Label(login_window, text="Username:").pack(pady=5)
    login_username = Entry(login_window)
    login_username.pack(pady=5)

    Label(login_window, text="Password:").pack(pady=5)
    login_password = Entry(login_window, show="*")
    login_password.pack(pady=5)

    Button(login_window, text="Login", command=login).pack(pady=20)
    Button(login_window, text="Signup", command=lambda: [login_window.destroy(), signup_page()]).pack(pady=10)

    login_window.mainloop()

# Signup window
def signup_page():
    global signup_window, signup_username, signup_password, signup_confirm_password, signup_secret_key
    signup_window = Tk()
    signup_window.title("Signup")
    signup_window.geometry("400x400")
    signup_window.resizable(False, False)

    Label(signup_window, text="Signup", font="Arial 18 bold").pack(pady=20)

    Label(signup_window, text="Username:").pack(pady=5)
    signup_username = Entry(signup_window)
    signup_username.pack(pady=5)

    Label(signup_window, text="Password:").pack(pady=5)
    signup_password = Entry(signup_window, show="*")
    signup_password.pack(pady=5)

    Label(signup_window, text="Confirm Password:").pack(pady=5)
    signup_confirm_password = Entry(signup_window, show="*")
    signup_confirm_password.pack(pady=5)

    # New entry for secret key
    Label(signup_window, text="Secret Key:").pack(pady=5)
    signup_secret_key = Entry(signup_window, show="*")  # Entry for secret key
    signup_secret_key.pack(pady=5)

    Button(signup_window, text="Signup", command=signup).pack(pady=20)

    signup_window.mainloop()

    login_page()

# Caesar cipher encryption and decryption
def caesar_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift = key % 26
            if char.isupper():
                encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, key):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shift = key % 26
            if char.isupper():
                decrypted_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            decrypted_text += char
    return decrypted_text

# Vigenère cipher encryption and decryption
def vigenere_encrypt(text, key):
    encrypted_text = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if char.isupper():
                encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            key_index += 1
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(text, key):
    decrypted_text = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if char.isupper():
                decrypted_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text


# Function to select the cipher type (Caesar or Vigenère)
def cipher_text_func():
    global current_secret_key  # Use the global secret key
    entered_key = secret_key_entry.get().strip()  # Get the entered secret key
    selected_cipher = cipher_choice.get()  # Get the selected cipher type

    if not entered_key:
        messagebox.showerror("Error", "Please enter the secret key before proceeding.")
        return

    if entered_key == current_secret_key:
        try:
            text = text1.get(1.0, END)
            if selected_cipher == "Caesar":
                numeric_key = int(entered_key)  # Convert the key to an integer
                ciphered = caesar_encrypt(text, numeric_key)
            elif selected_cipher == "Vigenère":
                ciphered = vigenere_encrypt(text, entered_key)
            else:
                raise ValueError("Invalid cipher type selected.")

            text1.delete(1.0, END)
            text1.insert(END, ciphered)
        except ValueError:
            messagebox.showerror("Error", "The secret key must be a valid input.")
    else:
        messagebox.showerror("Error", "The secret key entered does not match the one used during signup.")


# Function to decipher text based on selected cipher
def decipher_text_func():
    global current_secret_key  # Use the global secret key
    entered_key = secret_key_entry.get().strip()  # Get the entered secret key
    selected_cipher = cipher_choice.get()  # Get the selected cipher type

    if not entered_key:
        messagebox.showerror("Error", "Please enter the secret key before proceeding.")
        return

    if entered_key == current_secret_key:
        try:
            text = text1.get(1.0, END)
            if selected_cipher == "Caesar":
                numeric_key = int(entered_key)  # Convert the key to an integer
                deciphered = caesar_decrypt(text, numeric_key)
            elif selected_cipher == "Vigenère":
                deciphered = vigenere_decrypt(text, entered_key)
            else:
                raise ValueError("Invalid cipher type selected.")

            text1.delete(1.0, END)
            text1.insert(END, deciphered)
        except ValueError:
            messagebox.showerror("Error", "The secret key must be a valid input.")
    else:
        messagebox.showerror("Error", "The secret key entered does not match.")

# Image handling functions
def showimage():
    global filename
    filename = filedialog.askopenfilename(
        initialdir=os.getcwd(),
        title='Select Image File',
        filetypes=(("PNG file", "*.png"), ("JPG File", "*.jpg"), ("All files", "*.*"))
    )

    if filename:
        img = Image.open(filename)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image=img, width=250, height=250)
        lbl.image = img

def Hide():
    global secret
    if filename:
        message = text1.get(1.0, END).strip()
        key = secret_key_entry.get().strip()
        if not message or not key:
            messagebox.showerror("Error", "Message and key are required to hide data.")
            return

        try:
            numeric_key = int(key)  # Ensure the key is numeric
            encrypted_message = caesar_encrypt(message, numeric_key)
            secret = lsb.hide(filename, encrypted_message)
            messagebox.showinfo("Success", "Data hidden successfully!")
        except ValueError:
            messagebox.showerror("Error", "The key must be numeric for hiding data.")
        except lsb.HideError as e:
            messagebox.showerror("Error", f"Hiding data failed: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def Show():
    if filename:
        key = secret_key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Cipher key is required to reveal data.")
            return
        try:
            numeric_key = int(key)  # Ensure the key is numeric
            clear_message = lsb.reveal(filename)
            if clear_message:
                decrypted_message = caesar_decrypt(clear_message, numeric_key)
                text1.delete(1.0, END)
                text1.insert(END, decrypted_message)
            else:
                messagebox.showinfo("No Data", "No hidden data found in the selected image.")
        except ValueError:
            messagebox.showerror("Error", "The key must be numeric to reveal data.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    else:
        messagebox.showerror("Error", "No image selected.")

def save():
    global secret
    if secret:
        secret.save("hidden.png")

# Define main_app function
def main_app():
    global root, lbl, secret_key_entry, text1, cipher_choice
    root = Tk()
    root.title("The Silent Cipher")
    root.geometry("700x500+150+180")
    root.resizable(False, False)
    root.configure(bg="#003049")

    global filename, secret
    filename = None
    secret = None

    try:
        image_icon = PhotoImage(file="logo.png")
        root.iconphoto(False, image_icon)
    except Exception as e:
        messagebox.showwarning("Resource Warning", f"Could not load icon: {e}")

    try:
        logo = PhotoImage(file="logo.png")
        Label(root, image=logo, bg="#003049").place(x=10, y=0)
    except Exception as e:
        messagebox.showwarning("Resource Warning", f"Could not load logo: {e}")

    Label(root, text="The Silent Cipher", bg="#003049", fg="white", font="ariel 20 bold").place(x=100, y=20)

    f = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
    f.place(x=10, y=80)

    lbl = Label(f, bg="black")
    lbl.place(x=40, y=10)

    frame2 = Frame(root, bd=3, width=340, height=280, bg="white", relief=GROOVE)
    frame2.place(x=350, y=80)

    text1 = Text(frame2, font="Roboto 13", bg="white", fg="black", relief=GROOVE, wrap=WORD)
    text1.place(x=0, y=0, width=320, height=295)
    scrollbar1 = Scrollbar(frame2)
    scrollbar1.place(x=320, y=0, height=300)
    scrollbar1.configure(command=text1.yview)
    text1.configure(yscrollcommand=scrollbar1.set)

    secret_key_label = Label(root, text="Secret Key:", bg="#BC6C25", fg="white", font="ariel 10 bold")
    secret_key_label.place(x=350, y=50)
    secret_key_entry = Entry(root, width=20, font="ariel 10", show="*")
    secret_key_entry.place(x=430, y=50)

    # Add RadioButton for cipher selection
    cipher_choice = StringVar()
    cipher_choice.set("Caesar")  # Default choice
    cipher_choice_menu = OptionMenu(root, cipher_choice, "Caesar", "Vigenère")
    cipher_choice_menu.place(x=590, y=40)

    # Cipher and Decipher buttons
    Button(root, text="Cipher", command=cipher_text_func).place(x=560, y=333)
    Button(root, text="Decipher", command=decipher_text_func).place(x=610, y=333)

    # Controls
    frame3 = Frame(root, bd=3, bg="#2f4155", width=330, height=100, relief=GROOVE)
    frame3.place(x=10, y=370)
    Button(frame3, text="Open Data", width=10, height=2, font="ariel 14 bold", command=showimage).place(x=20, y=30)
    Button(frame3, text="Save Data", width=10, height=2, font="ariel 14 bold", command=save).place(x=180, y=30)
    Label(frame3, text="Image, Audio file", bg="#2f4155", fg="yellow").place(x=20, y=5)

    frame4 = Frame(root, bd=3, bg="#2f4155", width=330, height=100, relief=GROOVE)
    frame4.place(x=360, y=370)
    Button(frame4, text="Hide Data", width=10, height=2, font="ariel 14 bold", command=Hide).place(x=20, y=30)
    Button(frame4, text="Show Data", width=10, height=2, font="ariel 14 bold", command=Show).place(x=180, y=30)
    Label(frame4, text="Encrypt and Decrypt", bg="#2f4155", fg="yellow").place(x=20, y=5)

    root.mainloop()

login_page()