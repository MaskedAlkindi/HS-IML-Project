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
from manage_apis import signup, login, get_logs, get_all_scans, create_log, create_scan

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

    return prediction, pe_features  # Return the prediction and the features used

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'token' not in st.session_state:
    st.session_state.token = None

# Define user authentication function
def user_auth():
    st.sidebar.title('User Authentication')
    auth_choice = st.sidebar.radio('Login/Signup', ['Login', 'Signup'])

    if auth_choice == 'Login':
        st.subheader('Login')
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        if st.button('Login'):
            response = login(username, password)
            if 'token' in response:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.token = response['token']
                st.success('Logged in successfully!')
                create_log("Login", f"{username} logged in.", st.session_state.token)
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
            response = signup(username, first_name, last_name, password, 'user')
            if 'message' in response and response['message'] == 'User created successfully':
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success('Account created successfully!')
                create_log("Signup", f"{username} signed up.", st.session_state.token)
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
        create_log("Setup Telegram Bot", "Telegram bot setup and deployed.", st.session_state.token)

# Function to display statistics
def show_statistics():
    st.title('Statistics')
    if 'token' in st.session_state and st.session_state.token:
        scans_response = get_all_scans(st.session_state.token)
        if 'error' in scans_response:
            st.error(scans_response['error'])
        else:
            # Extracting data from response
            all_scans = scans_response['allScans']
            today_scans = scans_response['todayScans']
            week_scans = scans_response['weekScans']
            month_scans = scans_response['monthScans']
            year_scans = scans_response['yearScans']

            if not all_scans:
                st.warning("No scan data available to display statistics.")
                return

            # Convert data to DataFrame
            df_all = pd.DataFrame(all_scans)
            df_today = pd.DataFrame(today_scans)
            df_week = pd.DataFrame(week_scans)
            df_month = pd.DataFrame(month_scans)
            df_year = pd.DataFrame(year_scans)

            # Display statistics
            st.subheader('Total Scans')
            st.write(f"All time: {len(df_all)}")
            st.write(f"Today: {len(df_today)}")
            st.write(f"This week: {len(df_week)}")
            st.write(f"This month: {len(df_month)}")
            st.write(f"This year: {len(df_year)}")

            # Plot total scans over time
            st.subheader('Scans Over Time')
            df_all['TimeStamp'] = pd.to_datetime(df_all['TimeStamp'])
            df_all.set_index('TimeStamp', inplace=True)
            scans_over_time = df_all.resample('D').size()
            fig = px.line(scans_over_time, title='Total Scans Over Time')
            st.plotly_chart(fig)

            # Distribution of scans by type (malware/legitimate)
            st.subheader('Malware vs Legitimate Scans')
            malware_counts = df_all['IsMalware'].value_counts()
            fig = px.pie(values=malware_counts, names=['Legitimate', 'Malware'], title='Distribution of Malware and Legitimate Scans')
            st.plotly_chart(fig)

            # Bar chart for scans by time period
            st.subheader('Scans by Time Period')
            time_periods = ['Today', 'This Week', 'This Month', 'This Year']
            counts = [len(df_today), len(df_week), len(df_month), len(df_year)]
            fig = px.bar(x=time_periods, y=counts, title='Scans by Time Period', labels={'x':'Time Period', 'y':'Number of Scans'})
            st.plotly_chart(fig)
    else:
        st.error("Authentication token not available. Please log in.")

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
        create_log("Model Deployment", f"Model {model_filename} deployed with accuracy {accuracy:.2f}.", st.session_state.token)

# Function to display logs
def show_logs():
    st.title('Logs')
    if 'token' in st.session_state and st.session_state.token:
        logs_response = get_logs(st.session_state.token)
        if 'error' in logs_response:
            st.error(logs_response['error'])
        else:
            for log in logs_response:
                with st.expander(f"Log ID: {log['LogID']}"):
                    st.write(f"Username: {log['Username']}")
                    st.write(f"Action: {log['Action']}")
                    st.write(f"TimeStamp: {log['TimeStamp']}")
    else:
        st.error("Authentication token not available. Please log in.")

def upload_file_view_characteristics():
    st.title('Upload File and View All Characteristics')

    # Section to view and select existing datasets
    st.subheader('Select Existing Dataset or Create New')
    existing_datasets = [f for f in os.listdir(DATASETS_PATH) if f.startswith('malware') and f.endswith('.csv')]
    existing_datasets.insert(0, "Create New Dataset")
    selected_dataset = st.selectbox('Select Dataset', existing_datasets)

    if selected_dataset == "Create New Dataset":
        st.subheader('Create New Dataset')
        dataset_number = st.text_input('Enter the new dataset number')
        create_dataset = st.button('Create Dataset')

        if create_dataset:
            if dataset_number:
                new_dataset_path = os.path.join(DATASETS_PATH, f'malware_{dataset_number}.csv')
                original_dataset_path = os.path.join(DATASETS_PATH, 'malware.csv')
                if os.path.exists(original_dataset_path):
                    try:
                        if not os.path.exists(new_dataset_path):
                            # Copy the original dataset to the new dataset
                            pd.read_csv(original_dataset_path).to_csv(new_dataset_path, index=False)
                            st.success(f'New dataset created successfully: malware_{dataset_number}.csv')
                            selected_dataset = f'malware_{dataset_number}.csv'
                            create_log("Create Dataset", f"Created new dataset: malware_{dataset_number}.csv", st.session_state.token)
                        else:
                            st.warning(f'Dataset malware_{dataset_number}.csv already exists.')
                    except Exception as e:
                        st.error(f'Failed to create new dataset: {e}')
                else:
                    st.warning('Original dataset malware.csv does not exist.')
            else:
                st.warning('Please enter a valid dataset number.')

    # Section to upload and analyze a PE file
    st.subheader('Upload and Analyze a PE File')
    uploaded_file = st.file_uploader("Upload a PE file", type=["exe", "dll"])
    legitimate = st.selectbox("Legitimate?", ["Yes", "No"])

    if uploaded_file is not None:
        with NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_file_path = tmp_file.name

        view_characteristics(tmp_file_path)

        if selected_dataset != "Create New Dataset":
            if st.button('Add to Dataset'):
                try:
                    dataset_path = os.path.join(DATASETS_PATH, selected_dataset)
                    add_to_dataset(tmp_file_path, uploaded_file.name, legitimate)
                    st.success(f'File characteristics added to the dataset: {selected_dataset}')
                    create_log("Add to Dataset", f"Added file characteristics to {selected_dataset}.", st.session_state.token)
                except Exception as e:
                    st.error(f'Failed to add file characteristics to the dataset: {e}')
        else:
            st.warning('Please create or select a dataset to add the file characteristics.')

def view_dataset_page():
    st.title('View Dataset')
    
    # List available CSV files in the datasets directory
    csv_files = [f for f in os.listdir(DATASETS_PATH) if f.endswith('.csv')]
    
    if not csv_files:
        st.write("No datasets found in the directory.")
        return

    # Select a dataset
    selected_dataset = st.selectbox('Select a Dataset', ["Select a dataset"] + csv_files)

    if selected_dataset != "Select a dataset":
        dataset_path = os.path.join(DATASETS_PATH, selected_dataset)
        if os.path.exists(dataset_path):
            try:
                df = pd.read_csv(dataset_path, on_bad_lines='skip')
                st.dataframe(df)
                create_log("View Dataset", f"Viewed dataset: {selected_dataset}", st.session_state.token)
            except pd.errors.ParserError as e:
                st.error(f"Error parsing CSV file: {e}")
        else:
            st.write("Selected dataset does not exist.")



# Add the function to the main app logic
if not st.session_state.logged_in:
    user_auth()
else:
    st.sidebar.title('Navigation')
    st.sidebar.markdown(f"### Welcome, {st.session_state.username}")
    choice = st.sidebar.selectbox('Select Page', ['Predict Malware', 'Upload File', 'View Dataset', 'Setup Telegram Bot', 'Statistics', 'Re-train Model', 'Logs'])

    if choice == 'Predict Malware':
        st.title('Upload and Predict Malware')
        uploaded_file = st.file_uploader("Choose a PE file", type=["exe", "dll"])
        model_files = [f for f in os.listdir(MODELS_PATH) if f.endswith('.joblib')]
        selected_model = st.selectbox("Select Model", model_files)
        if uploaded_file is not None and selected_model:
            with NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_file_path = tmp_file.name
            
            prediction, features = predict_malicious(tmp_file_path, selected_model)
            st.success("The file is malicious." if prediction else "The file is not malicious.")
            create_scan(features, prediction, st.session_state.token)
            create_log("Predict Malware", f"Prediction made using model {selected_model}. File is {'malicious' if prediction else 'not malicious'}.", st.session_state.token)

    elif choice == 'Upload File':
        upload_file_view_characteristics()

    elif choice == 'View Dataset':
        view_dataset_page()

    elif choice == 'Setup Telegram Bot':
        setup_telegram_bot()

    elif choice == 'Statistics':
        show_statistics()

    elif choice == 'Re-train Model':
        retrain_model()

    elif choice == 'Logs':
        show_logs()
