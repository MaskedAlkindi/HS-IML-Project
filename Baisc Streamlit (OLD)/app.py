import streamlit as st
import pefile
import array
import math
import joblib
import time
from tempfile import NamedTemporaryFile

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
    """Extract resources :
    [entropy, size]"""
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
    """Return version infos"""
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

    # Sections
    entropy = list(map(lambda x: x.get_entropy(), pe.sections))
    res['SectionsMaxEntropy'] = max(entropy) if entropy else 0

    # Resources
    resources = get_resources(pe)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
    else:
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0

    # Version information size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0

    return res

# Main function to predict if a PE file is malicious
def predict_malicious(file_path):
    # Load the trained model
    model_filename = "random_forest_100_estimators.joblib"
    model = joblib.load(model_filename)

    # Extract features from the PE file
    data = extract_infos(file_path)
    
    # Load the feature list used for training
    feature_list = [
        'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'ImageBase',
        'MajorOperatingSystemVersion', 'MajorSubsystemVersion', 'Subsystem',
        'DllCharacteristics', 'SizeOfStackReserve', 'SectionsMaxEntropy',
        'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'VersionInformationSize'
    ]

    # Prepare the feature array
    pe_features = [data.get(f, 0) for f in feature_list]

    # Predict using the trained model
    prediction = model.predict([pe_features])[0]

    # Output the prediction
    if prediction == 1:
        return "The file is malicious."
    else:
        return "The file is not malicious."

# Streamlit Application
st.title('Static Malware Classifier')

uploaded_file = st.file_uploader("Upload a PE file", type=["exe", "dll"])

if uploaded_file is not None:
    with st.spinner('Processing...'):
        # Save the uploaded file temporarily
        with NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_file_path = tmp_file.name
        
        # Run the prediction
        result = predict_malicious(tmp_file_path)
        st.success(result)
