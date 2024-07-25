# import streamlit as st
# import pefile
# import array
# import math
# import joblib
# import csv
# import os
# from tempfile import NamedTemporaryFile
# import pandas as pd
# import matplotlib.pyplot as plt
# import numpy as np
# import json
# import plotly.express as px
# import plotly.graph_objects as go

# from sklearn.ensemble import RandomForestClassifier
# from sklearn.tree import DecisionTreeClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import accuracy_score

# from manage_apis import signup, login

# # Function to calculate entropy
# def get_entropy(data):
#     if len(data) == 0:
#         return 0.0
#     occurences = array.array('L', [0]*256)
#     for x in data:
#         occurences[x if isinstance(x, int) else ord(x)] += 1

#     entropy = 0
#     for x in occurences:
#         if x:
#             p_x = float(x) / len(data)
#             entropy -= p_x*math.log(p_x, 2)

#     return entropy

# # Function to extract resources from the PE file
# def get_resources(pe):
#     resources = []
#     if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
#         try:
#             for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
#                 if hasattr(resource_type, 'directory'):
#                     for resource_id in resource_type.directory.entries:
#                         if hasattr(resource_id, 'directory'):
#                             for resource_lang in resource_id.directory.entries:
#                                 data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
#                                 size = resource_lang.data.struct.Size
#                                 entropy = get_entropy(data)
#                                 resources.append([entropy, size])
#         except Exception:
#             return resources
#     return resources

# # Function to get version information from the PE file
# def get_version_info(pe):
#     res = {}
#     for fileinfo in pe.FileInfo:
#         if fileinfo.Key == 'StringFileInfo':
#             for st in fileinfo.StringTable:
#                 for entry in st.entries.items():
#                     res[entry[0]] = entry[1]
#         if fileinfo.Key == 'VarFileInfo':
#             for var in fileinfo.Var:
#                 res[var.entry.items()[0][0]] = var.entry.items()[0][1]
#     if hasattr(pe, 'VS_FIXEDFILEINFO'):
#         res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
#         res['os'] = pe.VS_FIXEDFILEINFO.FileOS
#         res['type'] = pe.VS_FIXEDFILEINFO.FileType
#         res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
#         res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
#         res['signature'] = pe.VS_FIXEDFILEINFO.Signature
#         res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
#     return res

# # Function to extract information from the PE file
# def extract_infos(fpath):
#     res = {}
#     pe = pefile.PE(fpath)
#     res['Machine'] = pe.FILE_HEADER.Machine
#     res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
#     res['Characteristics'] = pe.FILE_HEADER.Characteristics
#     res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
#     res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
#     res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
#     res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
#     res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
#     res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
#     res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
#     res['SectionsMaxEntropy'] = 0
#     res['ResourcesMinEntropy'] = 0
#     res['ResourcesMaxEntropy'] = 0
#     res['VersionInformationSize'] = 0
    
#     resources = get_resources(pe)
#     if len(resources) > 0:
#         entropy = list(map(lambda x: x[0], resources))
#         res['ResourcesMinEntropy'] = min(entropy)
#         res['ResourcesMaxEntropy'] = max(entropy)
#     else:
#         res['ResourcesMinEntropy'] = 0
#         res['ResourcesMaxEntropy'] = 0

#     try:
#         version_infos = get_version_info(pe)
#         res['VersionInformationSize'] = len(version_infos)
#     except AttributeError:
#         res['VersionInformationSize'] = 0

#     return res

# # Function to add extracted characteristics to the CSV file
# def add_to_dataset(file_path, file_name, legitimate):
#     data = extract_infos(file_path)
#     csv_columns = [
#         'Name', 'md5', 'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion', 
#         'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 
#         'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 
#         'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage', 
#         'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 
#         'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 
#         'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 
#         'SectionsMeanVirtualsize', 'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 
#         'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 
#         'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize', 'legitimate'
#     ]

#     row = {col: data.get(col, 0) for col in csv_columns}
#     row['Name'] = file_name
#     row['legitimate'] = 1 if legitimate == 'Yes' else 0

#     file_exists = os.path.isfile('malware.csv')
#     with open('malware.csv', 'a', newline='') as csvfile:
#         writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
#         if not file_exists:
#             writer.writeheader()
#         writer.writerow(row)

# # Function to view characteristics of the uploaded PE file
# def view_characteristics(file_path):
#     data = extract_infos(file_path)
#     st.json(data)

# # Main function to predict if a PE file is malicious
# def predict_malicious(file_path):
#     model_filename = "random_forest_100_estimators.joblib"
#     model = joblib.load(model_filename)

#     data = extract_infos(file_path)
    
#     feature_list = [
#         'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'ImageBase',
#         'MajorOperatingSystemVersion', 'MajorSubsystemVersion', 'Subsystem',
#         'DllCharacteristics', 'SizeOfStackReserve', 'SectionsMaxEntropy',
#         'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'VersionInformationSize'
#     ]

#     pe_features = [data.get(f, 0) for f in feature_list]

#     prediction = model.predict([pe_features])[0]

#     if prediction == 1:
#         return "The file is malicious."
#     else:
#         return "The file is not malicious."



# # Define user authentication function
# def user_auth():
#     st.sidebar.title('User Authentication')
#     auth_choice = st.sidebar.radio('Login/Signup', ['Login', 'Signup'])

#     if auth_choice == 'Login':
#         st.subheader('Login')
#         username = st.text_input('Username')
#         password = st.text_input('Password', type='password')
#         if st.button('Login'):
#             response = login(username, password)
#             if 'token' in response:
#                 st.session_state.logged_in = True
#                 st.session_state.username = username
#                 st.session_state.token = response['token']
#                 st.success('Logged in successfully!')
#                 st.experimental_rerun()
#             else:
#                 st.error('Invalid credentials')

#     elif auth_choice == 'Signup':
#         st.subheader('Signup')
#         first_name = st.text_input('First Name')
#         last_name = st.text_input('Last Name')
#         username = st.text_input('Username')
#         password = st.text_input('Password', type='password')
#         if st.button('Signup'):
#             response = signup(username, first_name, last_name, password, 'user')
#             if 'message' in response and response['message'] == 'User created successfully':
#                 st.session_state.logged_in = True
#                 st.session_state.username = username
#                 st.success('Account created successfully!')
#                 st.experimental_rerun()
#             else:
#                 st.error('Error creating account')








# # Define function for Telegram bot setup
# def setup_telegram_bot():
#     st.title('Setup Telegram Bot')
#     bot_token = st.text_input('Add Bot Token')
#     setup_passkey = st.text_input('Setup Passkey')
#     deploy = st.button('Deploy')
#     toggle = st.toggle('Toggle Bot On/Off')
    
#     if deploy:
#         st.success('Bot deployed successfully!')
#         st.write(f'Bot Token: {bot_token}')
#         st.write(f'Setup Passkey: {setup_passkey}')
#         st.write(f'Bot Status: {"On" if toggle else "Off"}')




# # Define function for statistics page
# def show_statistics():
#     st.title('Statistics')

#     # Generate some mock data
#     data = np.random.randn(1000)
#     df = pd.DataFrame({
#         'x': np.arange(1000),
#         'y': data,
#         'category': np.random.choice(['A', 'B', 'C'], size=1000)
#     })

#     # Histogram
#     st.subheader('Example Histogram')
#     fig = px.histogram(df, x='y', nbins=30, title='Histogram of Data')
#     st.plotly_chart(fig)

#     # Line Chart
#     st.subheader('Example Line Chart')
#     fig = px.line(df, x='x', y='y', title='Line Chart of Data')
#     st.plotly_chart(fig)

#     # Scatter Plot
#     st.subheader('Example Scatter Plot')
#     fig = px.scatter(df, x='x', y='y', color='category', title='Scatter Plot of Data')
#     st.plotly_chart(fig)

#     # Box Plot
#     st.subheader('Example Box Plot')
#     fig = px.box(df, x='category', y='y', title='Box Plot of Data by Category')
#     st.plotly_chart(fig)




# # Define function for re-training the model
# def retrain_model():
#     st.title('Re-train Model')
    
#     # List available CSV files in the current directory
#     csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    
#     if not csv_files:
#         st.write("No CSV files found in the current directory.")
#         return

#     # File explorer to select a CSV file
#     selected_file = st.selectbox('Select a CSV file', csv_files)
    
#     # Select classifier type
#     classifier_type = st.selectbox('Select Classifier', ['Decision Tree', 'Random Forest'])
    
#     # Enter model version
#     model_version = st.text_input('Enter Version of Model')
    
#     if st.button('Deploy'):
#         # Load the dataset
#         data = pd.read_csv(selected_file)
        
#         # Ensure your dataset contains the necessary features and labels
#         if 'legitimate' not in data.columns:
#             st.error('The selected dataset does not contain the required "legitimate" column.')
#             return

#         # Assume all other columns are features
#         features = data.drop(columns=['legitimate'])
#         labels = data['legitimate']

#         # Split data into training and testing sets
#         X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)

#         # Train the selected model
#         if classifier_type == 'Decision Tree':
#             model = DecisionTreeClassifier()
#         elif classifier_type == 'Random Forest':
#             model = RandomForestClassifier(n_estimators=100)
        
#         model.fit(X_train, y_train)
        
#         # Evaluate the model
#         predictions = model.predict(X_test)
#         accuracy = accuracy_score(y_test, predictions)
#         st.write(f'Model accuracy: {accuracy:.2f}')
        
#         # Save the model
#         model_filename = f'{classifier_type.lower().replace(" ", "_")}_{model_version}.joblib'
#         joblib.dump(model, model_filename)
#         st.success(f'Model deployed successfully as {model_filename}')










# # Main app logic to include the login/signup and navigation
# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False

# if not st.session_state.logged_in:
#     user_auth()
# else:
#     st.sidebar.title('Navigation')
#     st.sidebar.markdown(f"### Welcome, {st.session_state.username}")
#     choice = st.sidebar.selectbox('Select Page', ['Predict Malware', 'Upload File', 'View Dataset', 'Setup Telegram Bot', 'Statistics', 'Re-train Model'])

#     if choice == 'Predict Malware':
#         st.title('Upload and Predict Malware')
#         uploaded_file = st.file_uploader("Choose a PE file", type=["exe", "dll"])
#         if uploaded_file is not None:
#             with NamedTemporaryFile(delete=False) as tmp_file:
#                 tmp_file.write(uploaded_file.read())
#                 tmp_file_path = tmp_file.name
            
#             result = predict_malicious(tmp_file_path)
#             st.success(result)

#     elif choice == 'Upload File':
#         st.title('Upload File and View All Characteristics')
#         uploaded_file = st.file_uploader("Upload a PE file", type=["exe", "dll"])
#         legitimate = st.selectbox("Legitimate?", ["Yes", "No"])
#         if uploaded_file is not None:
#             with NamedTemporaryFile(delete=False) as tmp_file:
#                 tmp_file.write(uploaded_file.read())
#                 tmp_file_path = tmp_file.name
            
#             view_characteristics(tmp_file_path)

#             if st.button('Add to Dataset'):
#                 add_to_dataset(tmp_file_path, uploaded_file.name, legitimate)
#                 st.success("File characteristics added to the dataset.")

#     elif choice == 'View Dataset':
#         st.title('View Dataset')
#         if os.path.exists('malware.csv'):
#             try:
#                 df = pd.read_csv('malware.csv', on_bad_lines='skip')
#                 st.dataframe(df)
#             except pd.errors.ParserError as e:
#                 st.error(f"Error parsing CSV file: {e}")
#         else:
#             st.write("No dataset found. Please upload some files first.")

#     elif choice == 'Setup Telegram Bot':
#         setup_telegram_bot()

#     elif choice == 'Statistics':
#         show_statistics()

#         # Add the new page to the main app logic
#     elif choice == 'Re-train Model':
#         retrain_model()


import streamlit as st
import pefile
import array
import math
import joblib
import csv
import os
from tempfile import NamedTemporaryFile
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import json
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score
from manage_apis import signup, login


# Paths for datasets and models
DATASETS_PATH = '/app/datasets'
MODELS_PATH = '/app/models'

# Function to calculate entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

# Function to extract resources from the PE file
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources

# Function to get version information from the PE file
def get_version_info(pe):
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

# Function to extract information from the PE file
def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SectionsMaxEntropy'] = 0
    res['ResourcesMinEntropy'] = 0
    res['ResourcesMaxEntropy'] = 0
    res['VersionInformationSize'] = 0
    
    resources = get_resources(pe)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
    else:
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0

    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos)
    except AttributeError:
        res['VersionInformationSize'] = 0

    return res

# Function to add extracted characteristics to the CSV file
def add_to_dataset(file_path, file_name, legitimate):
    data = extract_infos(file_path)
    csv_columns = [
        'Name', 'md5', 'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion', 
        'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 
        'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 
        'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage', 
        'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 
        'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 
        'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 
        'SectionsMeanVirtualsize', 'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 
        'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 
        'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize', 'legitimate'
    ]

    row = {col: data.get(col, 0) for col in csv_columns}
    row['Name'] = file_name
    row['legitimate'] = 1 if legitimate == 'Yes' else 0

    dataset_path = os.path.join(DATASETS_PATH, 'malware.csv')
    file_exists = os.path.isfile(dataset_path)
    with open(dataset_path, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

# Function to view characteristics of the uploaded PE file
def view_characteristics(file_path):
    data = extract_infos(file_path)
    st.json(data)

# Main function to predict if a PE file is malicious
def predict_malicious(file_path, model_name):
    model_path = os.path.join(MODELS_PATH, model_name)
    model = joblib.load(model_path)

    data = extract_infos(file_path)
    
    feature_list = [
        'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'ImageBase',
        'MajorOperatingSystemVersion', 'MajorSubsystemVersion', 'Subsystem',
        'DllCharacteristics', 'SizeOfStackReserve', 'SectionsMaxEntropy',
        'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'VersionInformationSize'
    ]

    pe_features = [data.get(f, 0) for f in feature_list]

    prediction = model.predict([pe_features])[0]

    if prediction == 1:
        return "The file is not malicious."
    else:
        return "The file is malicious."

# # Define user authentication function
# def user_auth():
#     st.sidebar.title('User Authentication')
#     auth_choice = st.sidebar.radio('Login/Signup', ['Login', 'Signup'])

#     if auth_choice == 'Login':
#         st.subheader('Login')
#         username = st.text_input('Username')
#         password = st.text_input('Password', type='password')
#         if st.button('Login'):
#             response = login(username, password)
#             if 'token' in response:
#                 st.session_state.logged_in = True
#                 st.session_state.username = username
#                 st.session_state.token = response['token']
#                 st.success('Logged in successfully!')
#                 st.experimental_rerun()
#             else:
#                 st.error('Invalid credentials')

#     elif auth_choice == 'Signup':
#         st.subheader('Signup')
#         first_name = st.text_input('First Name')
#         last_name = st.text_input('Last Name')
#         username = st.text_input('Username')
#         password = st.text_input('Password', type='password')
#         if st.button('Signup'):
#             response = signup(username, first_name, last_name, password, 'user')
#             if 'message' in response and response['message'] == 'User created successfully':
#                 st.session_state.logged_in = True
#                 st.session_state.username = username
#                 st.success('Account created successfully!')
#                 st.experimental_rerun()
#             else:
#                 st.error('Error creating account')

# Define user authentication function
def user_auth():
    st.sidebar.title('User Authentication')
    auth_choice = st.sidebar.radio('Login/Signup', ['Login', 'Signup'])
    skip_login = st.sidebar.checkbox('Skip Login')

    if auth_choice == 'Login':
        st.subheader('Login')
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        if st.button('Login'):
            if skip_login:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success('Logged in successfully (bypassed)!')
                st.experimental_rerun()
            else:
                response = login(username, password)
                if 'token' in response:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.token = response['token']
                    st.success('Logged in successfully!')
                    st.experimental_rerun()
                else:
                    st.error('Invalid credentials')
    elif auth_choice == 'Signup':
        st.subheader('Signup')
        first_name = st.text_input('First Name')
        last_name = st.text_input('Last Name')
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        if st.button('Signup'):
            if skip_login:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success('Account created successfully (bypassed)!')
                st.experimental_rerun()
            else:
                response = signup(username, first_name, last_name, password, 'user')
                if 'message' in response and response['message'] == 'User created successfully':
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.success('Account created successfully!')
                    st.experimental_rerun()
                else:
                    st.error('Error creating account')




# Define function for Telegram bot setup
def setup_telegram_bot():
    st.title('Setup Telegram Bot')
    bot_token = st.text_input('Add Bot Token')
    setup_passkey = st.text_input('Setup Passkey')
    deploy = st.button('Deploy')
    toggle = st.toggle('Toggle Bot On/Off')
    
    if deploy:
        st.success('Bot deployed successfully!')
        st.write(f'Bot Token: {bot_token}')
        st.write(f'Setup Passkey: {setup_passkey}')
        st.write(f'Bot Status: {"On" if toggle else "Off"}')

# Define function for statistics page
def show_statistics():
    st.title('Statistics')

    # Generate some mock data
    data = np.random.randn(1000)
    df = pd.DataFrame({
        'x': np.arange(1000),
        'y': data,
        'category': np.random.choice(['A', 'B', 'C'], size=1000)
    })

    # Histogram
    st.subheader('Example Histogram')
    fig = px.histogram(df, x='y', nbins=30, title='Histogram of Data')
    st.plotly_chart(fig)

    # Line Chart
    st.subheader('Example Line Chart')
    fig = px.line(df, x='x', y='y', title='Line Chart of Data')
    st.plotly_chart(fig)

    # Scatter Plot
    st.subheader('Example Scatter Plot')
    fig = px.scatter(df, x='x', y='y', color='category', title='Scatter Plot of Data')
    st.plotly_chart(fig)

    # Box Plot
    st.subheader('Example Box Plot')
    fig = px.box(df, x='category', y='y', title='Box Plot of Data by Category')
    st.plotly_chart(fig)

def retrain_model():
    st.title('Re-train Model')
    
    # List available CSV files in the datasets directory
    csv_files = [f for f in os.listdir(DATASETS_PATH) if f.endswith('.csv')]
    
    if not csv_files:
        st.write("No CSV files found in the datasets directory.")
        return

    # File explorer to select a CSV file
    selected_file = st.selectbox('Select a CSV file', csv_files)
    
    # Select classifier type
    classifier_type = st.selectbox('Select Classifier', ['Decision Tree', 'Random Forest'])
    
    # Enter model version
    model_version = st.text_input('Enter Version of Model')
    
    if st.button('Deploy'):
        # Load the dataset
        data = pd.read_csv(os.path.join(DATASETS_PATH, selected_file), sep='|')
        
        # Ensure your dataset contains the necessary features and labels
        if 'legitimate' not in data.columns:
            st.error('The selected dataset does not contain the required "legitimate" column.')
            return

        # Assume all other columns are features
        features = data.drop(columns=['Name', 'md5', 'legitimate'])
        labels = data['legitimate']

        # Feature selection
        extratrees = ExtraTreesClassifier().fit(features, labels)
        model = SelectFromModel(extratrees, prefit=True)
        features_new = model.transform(features)
        nbfeatures = features_new.shape[1]

        st.write(f'Number of selected features: {nbfeatures}')

        # Get the names of the selected features
        selected_features = features.columns[model.get_support()]

        st.write('Selected feature names:')
        for feature in selected_features:
            st.write(feature)

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(features_new, labels, test_size=0.3, stratify=labels, random_state=42)

        # Train the selected model
        if classifier_type == 'Decision Tree':
            model = DecisionTreeClassifier()
        elif classifier_type == 'Random Forest':
            model = RandomForestClassifier(n_estimators=100)
        
        model.fit(X_train, y_train)
        
        # Evaluate the model
        predictions = model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        st.write(f'Model accuracy: {accuracy:.2f}')
        
        # Save the model
        model_filename = f'{classifier_type.lower().replace(" ", "_")}_{model_version}.joblib'
        joblib.dump(model, os.path.join(MODELS_PATH, model_filename))
        st.success(f'Model deployed successfully as {model_filename}')








# Main app logic to include the login/signup and navigation
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    user_auth()
else:
    st.sidebar.title('Navigation')
    st.sidebar.markdown(f"### Welcome, {st.session_state.username}")
    choice = st.sidebar.selectbox('Select Page', ['Predict Malware', 'Upload File', 'View Dataset', 'Setup Telegram Bot', 'Statistics', 'Re-train Model'])

    if choice == 'Predict Malware':
        st.title('Upload and Predict Malware')
        uploaded_file = st.file_uploader("Choose a PE file", type=["exe", "dll"])
        model_files = [f for f in os.listdir(MODELS_PATH) if f.endswith('.joblib')]
        selected_model = st.selectbox("Select Model", model_files)
        if uploaded_file is not None and selected_model:
            with NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_file_path = tmp_file.name
            
            result = predict_malicious(tmp_file_path, selected_model)
            st.success(result)

    elif choice == 'Upload File':
        st.title('Upload File and View All Characteristics')
        uploaded_file = st.file_uploader("Upload a PE file", type=["exe", "dll"])
        legitimate = st.selectbox("Legitimate?", ["Yes", "No"])
        if uploaded_file is not None:
            with NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_file_path = tmp_file.name
            
            view_characteristics(tmp_file_path)

            if st.button('Add to Dataset'):
                add_to_dataset(tmp_file_path, uploaded_file.name, legitimate)
                st.success("File characteristics added to the dataset.")

    elif choice == 'View Dataset':
        st.title('View Dataset')
        dataset_path = os.path.join(DATASETS_PATH, 'malware.csv')
        if os.path.exists(dataset_path):
            try:
                df = pd.read_csv(dataset_path, on_bad_lines='skip')
                st.dataframe(df)
            except pd.errors.ParserError as e:
                st.error(f"Error parsing CSV file: {e}")
        else:
            st.write("No dataset found. Please upload some files first.")

    elif choice == 'Setup Telegram Bot':
        setup_telegram_bot()

    elif choice == 'Statistics':
        show_statistics()

    elif choice == 'Re-train Model':
        retrain_model()