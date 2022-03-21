##Password manager GUI by 0p4que

##Imports
from tkinter import * #Tkinter for gui
from tkinter import ttk #ttk for gui theming
from PIL import ImageTk, Image #Pillow for gui images
from os.path import isfile #os.path.isfile to check for required files
from os import urandom, remove #urandom for generating random passwords
import string, random #string and random for generating random passwords
from hashlib import sha3_256 #SHA3_256 for hashing the main vault password
from pysqlitecipher import sqlitewrapper #pysqlitecipher for an encrypted SQL database
from datetime import datetime #datetime for time and date on log

##Logging function
def log(data): #Defines a function
    time = datetime.now() #Get the current time
    file = open("log.txt", "a") #open the logfile in append mode
    file.write("[" + str(time.day) + "/" + str(time.month) + "/" + str(time.year) + " at " + str(time.hour) + ":" + str(time.minute) + "]: " + str(data) + "\n") #Write the date and time plus the data to the log
    file.close() #Close the logfile

if isfile("log.txt"): #If logfile found
    log("Program started") 
else: #If logfile not found
    log("Program started")
    log("New logfile created")

global fileCheck
global authEntry    ##Declare global variables for checking authentication
global auth 

authenticated = False #Set authenticated to false

def login(): #Authentication window login function
    global authenticated ##Use global variables authenticated and vaultPass
    global vaultPass
    if fileCheck == True: #If vault and datafile already exist
        hashfile = open("data", "r") #Read password data file
        hashedPass = hashfile.readlines() #Save password hash to variable
        hashfile.close() #Close the password data file
        vaultPass = authEntry.get()  #Get the data from the login entry
        if sha3_256(authEntry.get().encode()).hexdigest() == hashedPass[0]: #If the hashed input matches the saved hash
            log("Logged in successfully")
            authenticated = True #Set global var authenticated to True so the rest of the program continues after this
            auth.destroy() #Destroy the login window
        else: #Hashed password doesnt match the saved hash
            log("Failed login attempt")
            authenticated = False #Set the global var authenticated to False so the vault root window never opens
    else: #If vault and datafile not found
        log("Vault data missing or not detected, creating new...")
        hashfile = open("data", "w+") #Open new data file
        vaultPass = authEntry.get() #set the vaultPass to the login entry's value
        hashfile.write(sha3_256(authEntry.get().encode()).hexdigest()) #Write the hashed password to the data file
        hashfile.close() #Close the data file
        log("New datafile created")
        auth.destroy() #Destroy the login window
        authenticated = True #Set authenticated variable to True

auth = Tk() #Open the login window
authStyle = ttk.Style(auth) #Give the login window a style
authStyle.theme_use("vista") #Set the login window style
auth.title("0Vault") #Set the login window title
auth.geometry("224x129") #Set the login window size
auth.resizable(0, 0) #Set the login window as not resizable
authImage = Image.open("0vault.png") #Open the banner image
authImage = authImage.resize((220, 60), Image.ANTIALIAS) #Resize the banner image
authImage = ImageTk.PhotoImage(authImage) 
authPanel = Label(auth, image=authImage) #Use the banner image in a label
authLabel = ttk.Label(auth) #Declare the login window, contents to be determined later
authEntry = ttk.Entry(auth, show="●") #Declare the login window entry box set not to show password
authButton = ttk.Button(auth, command=login) #Declare the login window button, contents determined later
showButton = ttk.Button(auth, text="Show") #Declare the show password button
auth.bind("<Return>", lambda event:login()) #Bind the enter key to the login function

if isfile("data") and isfile("vault.db"): #If vault and data files found
    authLabel.config(text="Enter your password") #Set auth label and auth buttons to value used when a vault exists
    authButton.config(text="Login")
    fileCheck = True #Set filecheck to True so the program knows that the files where already there
    log("Data file found")
else: #If vault and data files not found
    authLabel.config(text="Enter a password to create a new vault: ") #Set auth label and auth buttons to value used when a vault hasnt been found
    authButton.config(text="Create Vault!")
    fileCheck = False #Set filecheck to False so the program knows that the files weren't found on startup

def showPass(): #Function for show password toggle button
    if authEntry["show"] == "●": 
        authEntry["show"] = ""
    else:
        authEntry["show"] = "●"

showButton.config(command=showPass) #Set show button's command to showPass

authPanel.grid()                                                                            ##Organise the login window widgets
authLabel.grid()
authEntry.grid(ipadx=47, padx=1)
authButton.grid(row=3, ipadx=18, padx=(1, 1), sticky=E)
showButton.grid(row=3, ipadx=18, padx=(0, 1), sticky=W) 
auth.mainloop()                                                                             ##Login window mainloop

if authenticated == True: #If authenticated is true then open the vault
    if fileCheck == True: #If data and vault files already existed on startup
        con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=False , password=vaultPass) #Connect to existing vault
        log("Vault file found")
    else: #If data and vault files not found on startup
        con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=False , password=vaultPass) #Connect to new vault
        colList = [["Url", "TEXT"], ["Username", "TEXT"], ["Password", "TEXT"],]  ##
        con.createTable("vault", colList, makeSecure=True, commit=True)     ##Set up table in vault
        log("Vault created")

    global tableData #Declare tableData as global variable
    table = con.getDataFromTable("vault") #Get table as nested list from vault
    tableData = table[1] #Seperate items from table title
    
    global rootListbox     ##
    global rootText          ## Declare global variables for root widgets
    global rootLabel2      ##
    global editRootState  ##
    global addRootState  ## Declare global variables for window open states, so duplicate windows can't be opened
    global rusState          ##
    editRootState = False  ##
    addRootState = False  ## Set global variables for window states
    rusState = False          ##
    
    def DBedit(): #Edit database function
        global editRootState ##
        global addRootState ## Use global variables
        if editRootState == False and addRootState == False: #If other windows not already open
            if rootListbox.get(rootListbox.curselection()) == "": #Check for a blank selection in the listbox if so do nothing
                pass
            else: #If the listbox has something selected
                global selectedRow #Declare global variable selectedRow so the program knows which row to edit in the database later
                editRoot = Tk() #Start edit window
                editRootState = True #Declare edit window state as true
                editRootStyle = ttk.Style() #Give edit window a style
                editRootStyle.theme_use("vista") #Set edit window style
                editRoot.title("Edit Password") #Set edit window title
                spinboxVar = IntVar(editRoot)                         ## 
                urlConfigVar = StringVar(editRoot)                 ## Declare edit window variables
                usernameConfigVar = StringVar(editRoot)     ##
                passwordConfigVar = StringVar(editRoot)     ##
                con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=True , password=vaultPass) #Connect to database with vaultPass
                con.updateIDs("vault", commit=True) #Update database IDs
                table = con.getDataFromTable("vault") ##
                tableData = table[1]                                ##Fetch table data from database
                for i in tableData: #Iterate through table data
                    if i[1] == rootListbox.get(rootListbox.curselection()): #Look for listbox selection in tabledata
                        selectedRow = i[0]                   ##
                        urlConfigVar.set(i[1])                ## Display selected table data in edit window
                        usernameConfigVar.set(i[2])   ##
                        passwordConfigVar.set(i[3])   ##

                editTitle = ttk.Label(editRoot, text="Edit Password")                                      ## Declare edit window widgets
                editLabel = ttk.Label(editRoot, text="URL: \nUsername: \nPassword: ")       ##
                urlEntry = ttk.Entry(editRoot, textvariable=urlConfigVar)                               ## Using previously set varibles in entry boxes
                usernameEntry = ttk.Entry(editRoot, textvariable=usernameConfigVar)
                passwordEntry = ttk.Entry(editRoot, textvariable=passwordConfigVar)
                deleteButton = ttk.Button(editRoot, text="Delete")
                saveButton = ttk.Button(editRoot, text="Save")
                randomButton = ttk.Button(editRoot, text="Random")
                randomLengthMenu = ttk.Spinbox(editRoot, from_=0, to=26, width=3, textvariable=spinboxVar) ##Spinbox to select random password length
                randomLengthMenu.set(16) ##Set spinbox default value

                def deletePass(): #Delete password data from vault function
                    global rusState #Use global variable rus state
                    if rusState == False: #If rus window not open
                        rus = Tk() #Start rus window
                        rusStyle = ttk.Style(rus)
                        rusStyle.theme_use("vista")
                        rusState = True #Set rusState as True so duplicate window isn't opened
                        rus.title("Are you sure?")
                        def yesBtn(): #Yes button function
                            con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=True , password=vaultPass) ##Connect to database
                            con.deleteDataInTable("vault", selectedRow, commit=True, raiseError=True, updateId=False)  #Delete selected row                       
                            con.updateIDs("vault", commit=True) #Update database IDs
                            table = con.getDataFromTable("vault") ## Fetch data from table to update root listbox
                            tableData = table[1]                                ##
                            rootListbox.delete(0, END) #Empty root listbox
                            for i in tableData: #Iterate through tableData
                                rootListbox.insert(END, i[1]) #Insert row names to listbox
                            rootText.config(state="normal")                                                 
                            rootText.delete("1.0", END)                                                    ## 
                            selectedData = "URL     : \nUsername:\nPassword:"           ## Reset root text       
                            rootText.insert(END, selectedData)                                      ##
                            rootText.config(state="disabled")
                            rootLabel2.config(text="")
                            global editRootState #Use global editRootState
                            editRootState = False #Set editRootState to False so edit window can be opened again
                            global rusState #Use global rusState
                            rusState = False #Set rusState to False so window can be opened again
                            rus.destroy()           ## Destroy rus and edit windows
                            editRoot.destroy()   ##
                            log("Data removed from database")
                        def noBtn(): #No button function
                            global rusState #Use global rusState
                            rusState = False #Set rusState to False so the window can be opened again
                            rus.destroy() #Destroy rus window
                        rusLabel = ttk.Label(rus, text="Are you sure you want \nto delete this password?")  ##
                        yesButton = ttk.Button(rus, text="Yes", command=yesBtn)                                            ## Configure widgets
                        noButton = ttk.Button(rus, text="No", command=noBtn)                                                 ##
                        rusLabel.grid()      ##
                        yesButton.grid()    ##Organise widgets
                        noButton.grid()      ##
                        def onClose(): #onClose function for rus window
                                global rusState #Use global rusState
                                rusState = False #Set rusState to false so it can be opened again
                                rus.destroy() #Destroy the rus window
                        rus.protocol("WM_DELETE_WINDOW", onClose) #Bind red X to run onClose function
                        rus.mainloop() #rus mainloop
                    
                def savePass(): #Save password function 
                    con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=True , password=vaultPass)      ##
                    con.updateInTable("vault" , selectedRow, "Url", urlEntry.get(), commit = True , raiseError = True)                          ##
                    con.updateInTable("vault" , selectedRow, "Username", usernameEntry.get(), commit = True , raiseError = True)  ## Connect to database and update selected values
                    con.updateInTable("vault" , selectedRow, "Password", passwordEntry.get(), commit = True , raiseError = True)   ## Then update database IDs
                    con.updateIDs("vault", commit=True)                                                                                                                          ##
                    table = con.getDataFromTable("vault")  ## Fetch data from table
                    tableData = table[1]                                 ##
                    rootListbox.delete(0, END)
                    for i in tableData:                         ## Repopulate root Listbox
                        rootListbox.insert(END, i[1])     ##
                    global editRootState  #Use global editRootState
                    editRootState = False #Set editRootState to false so the window can be opened again
                    editRoot.destroy() #Destroy the edit window

                def randomPass(): #Random password generation function
                    length = spinboxVar.get() #Get the password length from the spinbox
                    chars = string.ascii_letters + string.digits + '!@#$%^&*()_-=+' #Specia; characters to use in password generation
                    random.seed = (urandom(1024)) #set seed for random password generation
                    passwordEntry.delete(0, "end") #Empty password entry
                    passwordEntry.insert(0, ''.join(random.choice(chars) for i in range(length))) #Put random string in password entry
                
                saveButton.config(command=savePass)            ##
                deleteButton.config(command=deletePass)       ## Assign functions to buttons
                randomButton.config(command=randomPass)  ##

                editTitle.grid(row=0, column=0, columnspan=2)       ##
                editLabel.grid(row=1, column=0, rowspan=3)           ##
                urlEntry.grid(row=1, column=1, ipadx=50)                 ##
                usernameEntry.grid(row=2, column=1, ipadx=50)    ##
                passwordEntry.grid(row=3, column=1, ipadx=50)    ## Organise widgets
                deleteButton.grid(row=4, column=1)                        ##
                randomLengthMenu.grid(row=4, column=0)           ##
                saveButton.grid(row=4, column=1, sticky=E)           ##
                randomButton.grid(row=4, column=1, sticky=W)     ##
                def onClose(): #onClose function for edit window
                    global editRootState   ##
                    editRootState = False  ## Set editRootState to False so the window can be opened again
                    editRoot.destroy()        ##
                editRoot.protocol("WM_DELETE_WINDOW", onClose) #Bind red X to onClose function
                editRoot.mainloop() #Edit window mainloop
        else: #If edit window already open do nothing
            pass
            
    def DBadd(): #Add window function
        global addRootState ## Use global variables for window open status'
        global editRootState ##
        if addRootState == False and editRootState == False: #If no other windows open then open the add window
            addRoot = Tk() #Start the add window
            addRootState = True #Set addRootState to true so no other windows can be opened
            addRoot.title("Add Password")          ##
            addRootStyle = ttk.Style(addRoot)     ## Configure add window theme and title
            addRootStyle.theme_use("vista")      ##
            spinboxVar = IntVar(addRoot)  #Define the spinbox variable
            
            addTitle = ttk.Label(addRoot, text="Add Password")                                                                                         ##
            addLabel = ttk.Label(addRoot, text="URL: \nUsername: \nPassword: ")                                                          ##
            urlEntry = ttk.Entry(addRoot)                                                                                                                             ##
            usernameEntry = ttk.Entry(addRoot)                                                                                                                 ##
            passwordEntry = ttk.Entry(addRoot)                                                                                                                 ## Configure widgets
            saveButton = ttk.Button(addRoot, text="Save!")                                                                                                ##
            randomButton = ttk.Button(addRoot, text="Random")                                                                                       ##
            randomLengthMenu = ttk.Spinbox(addRoot, from_=0, to=26, width=3, textvariable=spinboxVar)                   ##
            randomLengthMenu.set(16)                                                                                                                               ##

            def saveDB(): #Save to database function
                con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=True , password=vaultPass) ##
                insertList = [urlEntry.get(), usernameEntry.get(), passwordEntry.get()]                                                               ## Connect to database and enter new values
                con.insertIntoTable("vault", insertList, commit=True)                                                                                           ## Then update IDs
                con.updateIDs("vault", commit=True)                                                                                                                    ##
                table = con.getDataFromTable("vault")
                tableData = table[1]
                rootListbox.delete(0, END)                    ##
                for i in tableData:                                   ## Repopulate root listbox
                    rootListbox.insert(END, i[1])               ##
                global addRootState   ##
                addRootState = False  ## Set editRootState to False so the window can be opened again
                addRoot.destroy()        ## and destroy the window
                log("Data added to database")

            def randomPass(): ##Random password function
                length = spinboxVar.get()
                chars = string.ascii_letters + string.digits + '!@#$%^&*()_-=+'
                random.seed = (urandom(1024))
                passwordEntry.delete(0, "end")
                passwordEntry.insert(0, ''.join(random.choice(chars) for i in range(length)))
                
            
            saveButton.config(command=saveDB)               ## Assign buttons functions
            randomButton.config(command=randomPass)  ##

            addTitle.grid(row=0, column=0, columnspan=2)                     #
            addLabel.grid(row=1, column=0, rowspan=3)                         #
            urlEntry.grid(row=1, column=1, ipadx=45)                               #
            usernameEntry.grid(row=2, column=1, ipadx=45)                  # Organise widgets
            passwordEntry.grid(row=3, column=1, ipadx=45)                  # 
            saveButton.grid(row=4, column=1, sticky=E)                         #    
            randomLengthMenu.grid(row=4, column=0)                         # 
            randomButton.grid(row=4, column=1, sticky=W)                   # 
            def onClose(): #onClose function for add window
                global addRootState   ##
                addRootState = False ## Set the addRootState to False so the window can be opened again
                addRoot.destroy()       ## Destroy the add window
            addRoot.protocol("WM_DELETE_WINDOW", onClose) #Bind the red X to onClose function
            addRoot.mainloop() #addRoot mainloop
        else: #If add window already open then do nothing
            pass
    
    root = Tk() #Start the root window
    rootStyle= ttk.Style(root)         ##
    rootStyle.theme_use("vista")   ## Configure root window style, resizability and title
    root.title("0Vault")                    ##
    root.resizable("0", "0")              ##

    rootLabel = ttk.Label(root, text="Vault: ")                                            ##
    rootListbox = Listbox(root, height=12, width=26)                                 ##
    rootLabel2 = ttk.Label(root)                                                                 ## Configure root widgets  
    rootText = Text(root, height=12, width=40)                                           ##
    addButton = ttk.Button(root, text="Add", command=DBadd)               ##                   
    editButton = ttk.Button(root, text="Edit", command=DBedit)               ##

    rootText.config(state="normal")                                     ##
    rootText.delete("1.0", END)                                             ##
    selectedData = "URL     : \nUsername:\nPassword:"     ## Configure root textbox
    rootText.insert(END, selectedData)                               ##
    rootText.config(state="disabled")                                   ##
    
    
    def refreshData(): #Refresh data function
        if rootListbox.get(rootListbox.curselection()) == "": #If root listbox selection is empty then do nothing
            pass
        else:
            rootLabel2.config(text=rootListbox.get(rootListbox.curselection())) #Set the title label to the title of the url of the row
            con = sqlitewrapper.SqliteCipher(dataBasePath="vault.db" , checkSameThread=True , password=vaultPass) ## Read the data from the database
            con.updateIDs("vault", commit=True)                                                                                                                     ##
            table = con.getDataFromTable("vault")
            tableData = table[1]                                                                                                                                  ##
            for i in tableData:                                                                                                                                     ##
                if i[1] == rootListbox.get(rootListbox.curselection()):                                                                          ##
                    rootText.config(state="normal")                                                                                                      ## Populate root textbox with selected password data
                    rootText.delete("1.0", END)                                                                                                              ##  from database
                    selectedData = "URL     : " + str(i[1]) + "\nUsername: " + str(i[2]) + "\nPassword: " + str(i[3])        ##
                    rootText.insert(END, selectedData)                                                                                                ##
                    rootText.config(state="disabled")                                                                                                   ##
    
    for i in tableData:                          ## Populate root listbox
        rootListbox.insert(END, i[1])      ##

    rootListbox.bind('<<ListboxSelect>>', lambda event:refreshData()) #Bind root listbox selection to refresh data in root text

    rootLabel.grid(row=0, column=0)                                                         ##
    rootLabel2.grid(row=0, column=1)                                                        ##        
    rootListbox.grid(row=1, column=0, padx=2)                                          ## Organise widgets  
    rootText.grid(row=1, column=1, padx=(1, 2))                                           ##               
    addButton.grid(row=2, column=0, sticky=W, ipadx=3, padx=(1, 0))       ##           
    editButton.grid(row=2, column=1, sticky=E, ipadx=0, padx=(0, 1))         ##
    root.mainloop() #Root mainloop
    log("Program exited")
        
else: #If program isn't authenticated, exit the program here
    log("Program exited")
