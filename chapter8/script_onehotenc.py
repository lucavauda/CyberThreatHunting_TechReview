import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import pandas as pd

# Create sample data
apps = ['bytes',
 'std1',
 'bytes_diff',
 'count1',
 'app_dns',
 'app_dropbox',
 'app_http',
 'app_rpc',
 'app_splunk',
 'app_ssl',
 'app_tcp',
 'app_udp',
 'app_unknown',
 'app_unknown-ssl',
 'app_windows_azure',
 'app_windows_marketplace',
 'app_windows_update']

# Create DataFrame
df_features = pd.DataFrame({'app': apps})

# Apply one-hot encoding
# Modification: Ensured prefix is used for consistency in column names
df_features_one_hot_enc = pd.get_dummies(df_features, columns=['app'], prefix='app', dtype=int)

# Get unique app categories from the one-hot encoded DataFrame columns
app_categories_full_names = [col for col in df_features_one_hot_enc.columns if col.startswith('app_')]
# Create display names (without the 'app_' prefix) for the headers
app_categories_display_names = [col.replace('app_', '') for col in app_categories_full_names]


# Create figure and axes
fig, ax = plt.subplots(figsize=(17, 11)) # Adjusted figure size for better spacing
# Modification: Adjusted subplot margins to accommodate title and rotated labels
plt.subplots_adjust(left=0.08, right=0.95, top=0.88, bottom=0.20)

# Define colors
left_color = '#8FD5D5'
right_color = '#F5EBCF'
grid_color = 'black'
text_color = 'black'

# Dimensions
cell_height = 0.8
left_width = 3.5 # Adjusted for potentially longer app names
right_cell_width = 1.2 # Adjusted for category name width
left_x_start = 0
right_x_start = left_x_start + left_width + 1

# Draw title
# Modification: Moved title slightly up by increasing the y-coordinate in figtext
plt.figtext(0.5, 0.95, 'ONE-HOT ENCODING', fontsize=28, ha='center', weight='bold')

# Draw left header "app"
plt.text(left_x_start + left_width/2, len(apps) + 1.4, 'app', fontsize=16, ha='center', va='center', weight='bold')

# Draw left column (original app names)
for i, app_name in enumerate(apps):
    y_pos = len(apps) - i
    rect = Rectangle((left_x_start, y_pos), left_width, cell_height,
                     facecolor=left_color, edgecolor=grid_color, linewidth=1)
    ax.add_patch(rect)
    # Modification: Reduced font size for app names in the left column
    plt.text(left_x_start + left_width/2, y_pos + cell_height/2, app_name,
             fontsize=9, ha='center', va='center') # Reduced font size

# Draw arrow
arrow_start_x = left_x_start + left_width + 0.2
arrow_end_x = right_x_start - 0.2
arrow_y = (len(apps) / 2) + (cell_height /2) + 0.1 # Centered arrow
plt.arrow(arrow_start_x, arrow_y, arrow_end_x - arrow_start_x, 0,
          head_width=0.4, head_length=0.2, fc='black', ec='black', linewidth=2)

# Draw right table (one-hot encoded)
# First draw headers (category names)
for j, category_display_name in enumerate(app_categories_display_names):
    x_pos = right_x_start + j * right_cell_width
    rect = Rectangle((x_pos, len(apps) + 1), right_cell_width, cell_height,
                     facecolor=right_color, edgecolor=grid_color, linewidth=1)
    ax.add_patch(rect)
    # Modification: Reduced font size for category names and rotated them
    plt.text(x_pos + right_cell_width/2, len(apps) + 1 + cell_height/2, category_display_name,
             fontsize=7, ha='right', va='bottom', rotation=45) # Reduced font, rotated, adjusted alignment

# Draw cells with 0s and 1s
# Modification: Correctly represent one-hot encoding by using values from df_features_one_hot_enc
for i in range(len(apps)): # Iterate based on the number of original apps/rows
    y_pos = len(apps) - i
    for j, category_full_name in enumerate(app_categories_full_names): # Iterate through the one-hot encoded columns
        x_pos = right_x_start + j * right_cell_width
        rect = Rectangle((x_pos, y_pos), right_cell_width, cell_height,
                         facecolor=right_color, edgecolor=grid_color, linewidth=1)
        ax.add_patch(rect)

        # Get the one-hot encoded value from the DataFrame
        # df_features_one_hot_enc is indexed from 0 to len(apps)-1, matching the loop for i
        value = df_features_one_hot_enc.loc[i, category_full_name]

        plt.text(x_pos + right_cell_width/2, y_pos + cell_height/2, str(value),
                 fontsize=12, ha='center', va='center', weight='bold')

# Set limits and remove axes
ax.set_xlim(left_x_start - 0.5, right_x_start + len(app_categories_display_names) * right_cell_width + 0.5)
ax.set_ylim(0.5, len(apps) + 2 + cell_height) # Ensure space for headers
ax.axis('off')

# Save the figure
plt.savefig('one_hot_encoding_visualization_refined.png', dpi=300)
plt.show()

print("Script refined and 'one_hot_encoding_visualization_refined.png' saved.")
# Verification prints
print("\nFirst 5 rows of the one-hot encoded DataFrame (df_features_one_hot_enc):")
print(df_features_one_hot_enc.head())
print(f"\nNumber of apps: {len(apps)}")
print(f"Number of rows in one-hot encoded DataFrame: {len(df_features_one_hot_enc)}")
print(f"Number of generated category columns (full names): {len(app_categories_full_names)}")
print(f"Number of display names for headers: {len(app_categories_display_names)}")
# Verify a specific encoding, e.g., for 'app_dns'
app_to_verify = 'app_dns' # Example app name that itself starts with 'app_'
if app_to_verify in apps:
    idx_verify = apps.index(app_to_verify) # Get original index
    print(f"\nOne-hot encoding for the app '{app_to_verify}' (original index {idx_verify}, DataFrame row {idx_verify}):")
    print(df_features_one_hot_enc.iloc[idx_verify])
    # When prefix='app' is used, and original column value is 'app_dns', the new column name becomes 'app_app_dns'
    # if original column value is 'bytes', the new column name becomes 'app_bytes'
    # app_categories_full_names correctly captures these (e.g., 'app_bytes', 'app_app_dns')
    # So, we need to find which of the app_categories_full_names corresponds to app_to_verify
    
    # Construct the expected column name based on how pd.get_dummies works with prefix
    expected_column_name = 'app_' + app_to_verify # This will be 'app_app_dns' for 'app_dns'
                                                # or 'app_bytes' for 'bytes'
                                                
    if expected_column_name in df_features_one_hot_enc.columns:
        print(f"Value in column '{expected_column_name}': {df_features_one_hot_enc.loc[idx_verify, expected_column_name]}" )
    else:
        # This case should ideally not be hit if logic is correct and app_to_verify is in original 'apps' list
        print(f"Error: Column '{expected_column_name}' not found for app '{app_to_verify}'. Check prefixing logic.")
else:
    print(f"\nApp '{app_to_verify}' not in the initial list.")
print("Script execution should now complete successfully and produce the visualization.")