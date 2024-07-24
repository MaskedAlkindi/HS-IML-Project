import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
import math
import joblib


# Load the dataset
dataset = pd.read_csv('malware.csv', sep='|')
data = pd.read_csv('malware.csv', sep='|')
X = data.drop(['Name', 'md5', 'legitimate'], axis=1)
y = data['legitimate']


# Feature selection
extratrees = ExtraTreesClassifier().fit(X, y)
model = SelectFromModel(extratrees, prefit=True)
X_new = model.transform(X)
nbfeatures = X_new.shape[1]


# Print number of features
print(f'Number of selected features: {nbfeatures}')

# Get the names of the selected features
selected_features = X.columns[model.get_support()]

# Print the names of the selected features
print('Selected feature names:')
for feature in selected_features:
    print(feature)



# Split the data
X_train, X_test, y_train, y_test = train_test_split(X_new, y, test_size=0.29, stratify=y)



num_rows = X_train.shape[0]
print(f'Number of training data rows: {num_rows}')

# Calculate the square root of the number of rows
sqrt_num_rows = math.sqrt(num_rows)
print(f'Square root of the number of training data rows: {sqrt_num_rows}')




# Train RandomForest model with 100 n_estimators
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Save the model to disk
model_filename = "random_forest_100_estimators.joblib"
joblib.dump(model, model_filename)

print(f"Model saved to {model_filename}")
