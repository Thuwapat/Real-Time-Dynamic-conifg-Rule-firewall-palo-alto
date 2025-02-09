import matplotlib.pyplot as plt
from sklearn.inspection import permutation_importance
import pandas as pd

# Function to check feature importance
def plot_feature_importance(model, features):
    importance = model.feature_importances_
    feature_importance = pd.DataFrame({'Feature': features, 'Importance': importance})
    feature_importance = feature_importance.sort_values(by='Importance', ascending=False)

    plt.figure(figsize=(10, 6))
    plt.barh(feature_importance['Feature'], feature_importance['Importance'])
    plt.xlabel('Importance Score')
    plt.ylabel('Feature')
    plt.title('Feature Importance')
    plt.gca().invert_yaxis()
    plt.show()

def plot_permutation_importance(model, X_test, y_test, features):
    result = permutation_importance(model, X_test, y_test, scoring="accuracy", random_state=42)
    importance = result.importances_mean

    feature_importance = pd.DataFrame({'Feature': features, 'Importance': importance})
    feature_importance = feature_importance.sort_values(by='Importance', ascending=False)

    plt.figure(figsize=(10, 6))
    plt.barh(feature_importance['Feature'], feature_importance['Importance'])
    plt.xlabel('Importance Score')
    plt.ylabel('Feature')
    plt.title('Permutation Feature Importance')
    plt.gca().invert_yaxis()
    plt.show()

