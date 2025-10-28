import streamlit as st
import json
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

# Page Configuration
st.set_page_config(
    page_title="Exposure Score Explainability",
    page_icon="🛡️",
    layout="wide"
)

# Load JSON data dynamically
@st.cache_data
def load_data():
    with open('sv_ac_high.json') as f:
        return json.load(f)

# Define Asset Criticality Attribute Mappings
@st.cache_data
def get_asset_criticality_mappings():
    """
    Define all possible values and their weightages for asset criticality attributes
    Based on the provided field specifications
    """
    return {
        "Type": {
            "field_weight": 8,
            "values": {
                "Server": 10,
                "Network Device": 8.71,
                "Hypervisor": 7.43,
                "Workstation": 6.14,
                "Mobile": 4.86,
                "Printer": 3.57,
                "Other": 2.29,
                "null": 1
            }
        },
        "Has Admin Privileges": {
            "field_weight": 5,
            "values": {
                "true": 10,
                "false": 5.5,
                "null": 1
            }
        },
        "Has High Privileges": {
            "field_weight": 5,
            "values": {
                "true": 10,
                "null": 1
            }
        },
        "Has Sensitive Info": {
            "field_weight": 5,
            "values": {
                "true": 10,
                "false": 5.5,
                "null": 1
            }
        },
        "Asset Compliance Scope": {
            "field_weight": 4,
            "values": {
                "PCI DSS": 10,
                "SOX": 5.5,
                "null": 1
            }
        },
        "Asset Role": {
            "field_weight": 4,
            "values": {
                "Domain Controller": 10,
                "Web Server": 8.88,
                "Database": 8.35,
                "Mail Server": 8.35,
                "ERP System": 7.82,
                "Cloud Instance": 7.82,
                "Hypervisor": 7.29,
                "AIX Server": 6.76,
                "DNS Server": 6.24,
                "Router": 5.71,
                "File Transfer Protocol": 5.18,
                "General Server": 4.65,
                "Virtual Desktop": 4.12,
                "Wireless Access Point": 3.59,
                "Mobile Device Management": 3.06,
                "General Purpose": 2.53,
                "Printer": 2,
                "Other": 1,
                "null": 1
            }
        },
        "Environment": {
            "field_weight": 3,
            "values": {
                "production": 10,
                "Production": 10,
                "prod": 10,
                "pe": 9.1,
                "staging": 8.2,
                "perfext": 7.3,
                "perf": 6.4,
                "perf-testing": 6.4,
                "qaregress": 5.5,
                "qasprint": 5.5,
                "qa": 5.5,
                "regress": 5.5,
                "integration": 4.6,
                "eng": 3.7,
                "engineering": 3.7,
                "devops": 2.8,
                "dev": 2.8,
                "developer": 2.8,
                "tpdev": 2.8,
                "ttv": 1.9,
                "null": 1
            }
        },
        "Business Unit": {
            "field_weight": 2,
            "values": {
                "Production Server": 10,
                "Customer Service": 10,
                "Global": 1,
                "Zone A Server": 1,
                "Zone B Omega Systems": 1,
                "PriorityAccess": 1,
                "Networking": 1,
                "Zone A Protect": 1,
                "Zone A Workstations": 1,
                "Zone B Workstations": 1,
                "Shared unity": 1,
                "null": 1
            }
        },
        "Organizational Unit": {
            "field_weight": 2,
            "values": {
                "Platform Engineering": 10,
                "null": 1
            }
        }
    }

data = load_data()
asset_crit_mappings = get_asset_criticality_mappings()

st.title("🛡️ Exposure Score Explainability Dashboard")
st.markdown("**Understand how your exposure score is calculated and explore what-if scenarios**")

# Extract core scoring parameters
if 'calculated_scores' in data and 'impact_base' in data['calculated_scores'] and isinstance(data['calculated_scores']['impact_base'], dict):
    asset_crit = data.get('calculated_scores', {}).get('impact_base', {}).get('asset_criticality', {}).get('overall_asset_criticality', 0)
    asset_crit_details = data.get('calculated_scores', {}).get('impact_base', {}).get('asset_criticality', {})
else:
    asset_crit = data.get('asset_criticality', {}).get('overall_asset_criticality', 0)
    asset_crit_details = data.get('asset_criticality', {})

cvss_base = data.get('cvss_base_score', 0)
epss = data.get('epss_score', 0)

# Store original modifiers from JSON
original_modifiers = data.get('modifiers', {})

# Helper Functions
def normalize_to_10(value, scale=1000):
    """Normalize values from 0-1000 scale to 1-10 scale"""
    return (value / scale) * 10

def calculate_asset_criticality_score(selected_attributes, mappings, excluded_fields):
    """
    Calculate asset criticality based on selected attributes
    Formula: Sum of (Field Weight × Field Value Weightage) / Sum of (Field Weight × Max Field Value) × 1000
    excluded_fields: set of field names to exclude from calculation
    """
    total_weighted_score = 0
    total_max_possible = 0
    breakdown = []
    
    for field_name, selected_value in selected_attributes.items():
        if field_name in mappings and field_name not in excluded_fields:
            field_config = mappings[field_name]
            field_weight = field_config['field_weight']
            value_weightage = field_config['values'].get(selected_value, 1)
            max_value_weightage = max(field_config['values'].values())
            
            weighted_score = field_weight * value_weightage
            max_weighted_score = field_weight * max_value_weightage
            
            total_weighted_score += weighted_score
            total_max_possible += max_weighted_score
            
            breakdown.append({
                'field': field_name,
                'value': selected_value,
                'field_weight': field_weight,
                'value_weightage': value_weightage,
                'weighted_score': weighted_score,
                'max_possible': max_weighted_score,
                'included': True
            })
        elif field_name in excluded_fields:
            # Add to breakdown but mark as excluded
            if field_name in mappings:
                field_config = mappings[field_name]
                breakdown.append({
                    'field': field_name,
                    'value': selected_value,
                    'field_weight': field_config['field_weight'],
                    'value_weightage': 0,
                    'weighted_score': 0,
                    'max_possible': 0,
                    'included': False
                })
    
    # Calculate normalized score (0-1000)
    if total_max_possible > 0:
        normalized_score = (total_weighted_score / total_max_possible) * 1000
    else:
        normalized_score = 0
    
    return {
        'score': normalized_score,
        'total_weighted_score': total_weighted_score,
        'total_max_possible': total_max_possible,
        'breakdown': breakdown
    }


def calculate_exposure_score(asset_crit_score, cvss_base_val, epss_val, active_modifiers):
    """Calculate exposure score with proper modifier application"""
    # Calculate impact
    impact_base_norm = normalize_to_10(asset_crit_score + cvss_base_val * 100, scale=2000)
    
    # Calculate likelihood - only using EPSS score
    likelihood_base_norm = normalize_to_10(epss_val * 1000, scale=1000)
    likelihood_with_mods = likelihood_base_norm
    likelihood_mods_applied = []
    likelihood_multiplier = 1.0

    for mod_key, is_active in active_modifiers.items():
        if mod_key in original_modifiers:
            mod_data = original_modifiers[mod_key]
            multiplier_config = mod_data.get('multiplier', {})
            applied_to = mod_data.get('applied_to', 'likelihood')

            if applied_to == 'likelihood':
                if isinstance(multiplier_config, dict):
                    multiplier = multiplier_config.get('true', 1.0) if is_active else multiplier_config.get('false', 1.0)
                else:
                    multiplier = multiplier_config if is_active else 1.0
                
                likelihood_multiplier *= multiplier
                status = "enabled" if is_active else "disabled"
                likelihood_mods_applied.append(f"{mod_key} ({status}: {multiplier}x)")

    likelihood_with_mods = likelihood_base_norm * likelihood_multiplier
    impact_final = impact_base_norm
    likelihood_final = min(likelihood_with_mods, 10.0)

    exposure_score_10 = np.sqrt((impact_final ** 2 + likelihood_final ** 2) / 2)
    exposure_score_1000 = exposure_score_10 * 100

    return {
        'impact_base': impact_base_norm,
        'likelihood_base': likelihood_base_norm,
        'impact_final': impact_final,
        'likelihood_multiplier': likelihood_multiplier,
        'likelihood_with_mods': likelihood_with_mods,
        'likelihood_final': likelihood_final,
        'exposure_score_10': exposure_score_10,
        'exposure_score_1000': exposure_score_1000,
        'likelihood_mods_applied': likelihood_mods_applied
    }

# Initialize session state for modifiers
if "modifier_states" not in st.session_state:
    st.session_state.modifier_states = {
        mod_key: mod_value.get("applies", False)
        for mod_key, mod_value in original_modifiers.items()
    }

# Initialize session state for asset criticality attributes
if "asset_crit_selections" not in st.session_state:
    st.session_state.asset_crit_selections = {
        field_name: list(field_config['values'].keys())[0]
        for field_name, field_config in asset_crit_mappings.items()
    }

# Initialize session state for excluded fields
if "excluded_fields" not in st.session_state:
    st.session_state.excluded_fields = set()

# Initialize session state for custom fields
if "custom_fields" not in st.session_state:
    st.session_state.custom_fields = {}

# Initialize session state for vulnerability scores
if "cvss_base_whatif" not in st.session_state:
    st.session_state.cvss_base_whatif = cvss_base
if "epss_whatif" not in st.session_state:
    st.session_state.epss_whatif = epss

# Function to save custom fields to config file
def save_custom_fields_to_config():
    """Save custom fields to the mappings configuration"""
    try:
        # This would be the ideal implementation to persist data
        # For now, we'll keep it in session state
        # In production, you'd write to a config file here
        pass
    except Exception as e:
        st.error(f"Error saving custom fields: {e}")

# Function to get combined mappings (original + custom)
def get_combined_mappings():
    """Combine original mappings with custom fields"""
    combined = asset_crit_mappings.copy()
    combined.update(st.session_state.custom_fields)
    return combined

# Sidebar: Vulnerability Score What-If Controls
st.sidebar.header("⚙️ Scenario Controls")
st.sidebar.markdown("Adjust vulnerability scores and modifiers to explore different risk scenarios")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Vulnerability Score What-If")

st.session_state.cvss_base_whatif = st.sidebar.slider(
    "CVSS Base Score",
    min_value=0.0,
    max_value=10.0,
    value=float(cvss_base),
    step=0.1,
    help="Impact Component: Adjust CVSS Base Score (0-10)"
)

st.session_state.epss_whatif = st.sidebar.slider(
    "EPSS Score",
    min_value=0.0,
    max_value=1.0,
    value=float(epss),
    step=0.001,
    format="%.3f",
    help="Likelihood Component: Exploitation Probability (0-1)"
)

# Sidebar: Modifier Controls
st.sidebar.markdown("---")
st.sidebar.markdown("### ⚡ Likelihood Modifiers")
for mod_key, mod_value in original_modifiers.items():
    pretty_name = mod_key.replace("_", " ").title()
    description = mod_value.get("description", "")
    multiplier_config = mod_value.get("multiplier", {})
    applied_to = mod_value.get("applied_to", "likelihood")

    if isinstance(multiplier_config, dict):
        multiplier_true = multiplier_config.get("true", 1.0)
        multiplier_false = multiplier_config.get("false", 1.0)
        effect = f"Enabled: {multiplier_true}x | Disabled: {multiplier_false}x"
    else:
        multiplier_true = multiplier_config
        effect = f"Enabled: {multiplier_true}x"

    current_state = st.sidebar.checkbox(
        f"{pretty_name}",
        value=st.session_state.modifier_states[mod_key],
        key=f"toggle_{mod_key}",
        help=f"{description}\n{effect}"
    )

    st.session_state.modifier_states[mod_key] = current_state

# Calculate current scores (using original asset criticality)
current_calc = calculate_exposure_score(
    asset_crit,
    st.session_state.cvss_base_whatif,
    st.session_state.epss_whatif,
    st.session_state.modifier_states
)

# Calculate original scores (without any modifiers and original vulnerability scores)
original_calc = calculate_exposure_score(
    asset_crit,
    cvss_base,
    epss,
    {k: v.get("applies", False) for k, v in original_modifiers.items()}
)

# ---------------------------------------------------
# Asset Criticality What-If Section
# ---------------------------------------------------
st.subheader("🏢 Asset Criticality What-If Analysis")
st.markdown("*Explore how different asset attributes affect the criticality score and overall exposure*")

# Button to create new field
col_button1, col_button2 = st.columns([1, 5])
with col_button1:
    if st.button("➕ Create New Field", use_container_width=True):
        st.session_state.show_create_field_dialog = True

# Dialog for creating new field
if st.session_state.get("show_create_field_dialog", False):
    with st.expander("🔧 Create New Asset Criticality Field", expanded=True):
        st.markdown("#### Add a custom field to the asset criticality calculation")
        
        dialog_col1, dialog_col2 = st.columns(2)
        
        with dialog_col1:
            new_field_name = st.text_input(
                "Field Name",
                placeholder="e.g., Data Sensitivity Level",
                help="Enter a unique name for this field",
                key="new_field_name"
            )
            
            new_field_weight = st.number_input(
                "Field Weight",
                min_value=1,
                max_value=10,
                value=3,
                help="Weight for this field (1-10, higher = more important)",
                key="new_field_weight"
            )
        
        with dialog_col2:
            st.markdown("##### Field Values & Weights")
            st.markdown("*Add at least 2 values for this field*")
         
        # Dynamic value input section
        if "new_field_values" not in st.session_state:
            st.session_state.new_field_values = [
                {"value": "", "weight": 10},
                {"value": "", "weight": 1}
            ]
        
        # st.markdown("---")
        
        # Display value inputs
        values_col1, values_col2, values_col3 = st.columns([3, 2, 1])
        
        with values_col1:
            st.markdown("**Value Name**")
        with values_col2:
            st.markdown("**Weight (1-10)**")
        with values_col3:
            st.markdown("**Action**")
        
        values_to_remove = []
        
        for idx, value_data in enumerate(st.session_state.new_field_values):
            val_col1, val_col2, val_col3 = st.columns([3, 2, 1])
            
            with val_col1:
                value_name = st.text_input(
                    f"Value {idx+1}",
                    value=value_data["value"],
                    placeholder=f"e.g., High, Medium, Low",
                    key=f"value_name_{idx}",
                    label_visibility="collapsed"
                )
                st.session_state.new_field_values[idx]["value"] = value_name
            
            with val_col2:
                value_weight = st.number_input(
                    f"Weight {idx+1}",
                    min_value=1.0,
                    max_value=10.0,
                    value=float(value_data["weight"]),
                    step=0.1,
                    key=f"value_weight_{idx}",
                    label_visibility="collapsed"
                )
                st.session_state.new_field_values[idx]["weight"] = value_weight
            
            with val_col3:
                if len(st.session_state.new_field_values) > 2:
                    if st.button("Remove", key=f"remove_value_{idx}", help="Remove this value"):
                        values_to_remove.append(idx)
        
        # Remove marked values
        for idx in reversed(values_to_remove):
            st.session_state.new_field_values.pop(idx)
        
        # Add new value button
        if st.button("➕ Add Another Value"):
            st.session_state.new_field_values.append({"value": "", "weight": 5})
            st.rerun()
        
        st.markdown("---")
        
        # Action buttons
        action_col1, action_col2, action_col3 = st.columns([1, 1, 3])
        
        with action_col1:
            if st.button("Create Field", type="primary", use_container_width=True):
                # Validate inputs
                if not new_field_name or new_field_name.strip() == "":
                    st.error("Please enter a field name")
                elif new_field_name in get_combined_mappings():
                    st.error("This field name already exists")
                else:
                    # Check if all values are filled
                    valid_values = [v for v in st.session_state.new_field_values if v["value"].strip() != ""]
                    
                    if len(valid_values) < 2:
                        st.error("Please add at least 2 values")
                    else:
                        # Create the new field
                        new_field = {
                            "field_weight": new_field_weight,
                            "values": {v["value"]: v["weight"] for v in valid_values}
                        }
                        
                        # Add to custom fields
                        st.session_state.custom_fields[new_field_name] = new_field
                        
                        # Initialize selection for this field
                        first_value = list(new_field["values"].keys())[0]
                        st.session_state.asset_crit_selections[new_field_name] = first_value
                        
                        # Save to config (optional - implement if needed)
                        save_custom_fields_to_config()
                        
                        # Reset and close dialog
                        st.session_state.show_create_field_dialog = False
                        st.session_state.new_field_values = [
                            {"value": "", "weight": 10},
                            {"value": "", "weight": 1}
                        ]
                        
                        st.success(f" Field '{new_field_name}' created successfully!")
                        st.rerun()
        
        with action_col2:
            if st.button("Cancel", use_container_width=True):
                st.session_state.show_create_field_dialog = False
                st.session_state.new_field_values = [
                    {"value": "", "weight": 10},
                    {"value": "", "weight": 1}
                ]
                st.rerun()

# Get combined mappings (original + custom)
combined_mappings = get_combined_mappings()

# Create two columns for the what-if controls
whatif_col1, whatif_col2 = st.columns([2, 1])

with whatif_col1:
    st.markdown("#### Configure Asset Attributes")
    
    # Show custom fields indicator if any exist
    # if st.session_state.custom_fields:
    #     st.info(f" {len(st.session_state.custom_fields)} custom field(s) added")
    
    # Create a grid of dropdowns for asset attributes
    attr_cols = st.columns(3)
    
    for idx, (field_name, field_config) in enumerate(combined_mappings.items()):
        col_idx = idx % 3
        with attr_cols[col_idx]:
            # Check if this is a custom field
            is_custom = field_name in st.session_state.custom_fields
            
            # Check if field is excluded
            is_excluded = field_name in st.session_state.excluded_fields
            
            # Add checkbox to exclude/include field at the top
            checkbox_label = f" {field_name}" + (" 🔧" if is_custom else "")
            is_included = st.checkbox(
                checkbox_label,
                value=not is_excluded,
                key=f"include_{field_name}",
                help=f"{'Custom field - ' if is_custom else ''}Uncheck to exclude (Field Weight: {field_config['field_weight']})"
            )
            
            # Update excluded fields set
            if not is_included:
                st.session_state.excluded_fields.add(field_name)
            else:
                st.session_state.excluded_fields.discard(field_name)
            
            options = list(field_config['values'].keys())
            
            # Initialize selection if not exists
            if field_name not in st.session_state.asset_crit_selections:
                st.session_state.asset_crit_selections[field_name] = options[0]
            
            current_value = st.session_state.asset_crit_selections.get(field_name, options[0])
            
            # Find current index
            try:
                current_idx = options.index(current_value)
            except ValueError:
                current_idx = 0
            
            # Show the selectbox with dynamic label
            if is_included:
                label = f"Value:"
            else:
                label = f"Value (Excluded):"
            
            selected = st.selectbox(
                label,
                options=options,
                index=current_idx,
                key=f"asset_attr_{field_name}",
                help=f"Select value for {field_name}",
                disabled=not is_included
            )
            
            st.session_state.asset_crit_selections[field_name] = selected
            
            # Add delete button for custom fields
            if is_custom:
                if st.button(f" Delete", key=f"delete_field_{field_name}", help="Delete this custom field"):
                    # Remove from custom fields
                    del st.session_state.custom_fields[field_name]
                    # Remove from selections
                    if field_name in st.session_state.asset_crit_selections:
                        del st.session_state.asset_crit_selections[field_name]
                    # Remove from excluded fields
                    st.session_state.excluded_fields.discard(field_name)
                    st.rerun()
            
            # Add visual separator
            st.markdown("---")

# Calculate new asset criticality
new_asset_crit_calc = calculate_asset_criticality_score(
    st.session_state.asset_crit_selections,
    combined_mappings,
    st.session_state.excluded_fields
)
new_asset_crit_score = new_asset_crit_calc['score']

# Calculate new exposure score with updated asset criticality and vulnerability scores
whatif_exposure_calc = calculate_exposure_score(
    new_asset_crit_score,
    st.session_state.cvss_base_whatif,
    st.session_state.epss_whatif,
    st.session_state.modifier_states
)

with whatif_col2:
    st.markdown("#### Impact Summary")
    
    # Asset Criticality Change
    ac_change = new_asset_crit_score - asset_crit
    ac_pct_change = (ac_change / asset_crit * 100) if asset_crit > 0 else 0
    
    st.metric(
        "Asset Criticality",
        f"{new_asset_crit_score:.0f}/1000"
    )
    
    # # Show number of excluded fields
    # if st.session_state.excluded_fields:
    #     st.info(f" {len(st.session_state.excluded_fields)} field(s) excluded")
    
    # Exposure Score Change
    exp_change = whatif_exposure_calc['exposure_score_1000'] - current_calc['exposure_score_1000']
    exp_pct_change = (exp_change / current_calc.get('exposure_score_1000', 0) * 100) if current_calc.get('exposure_score_1000', 0) > 0 else 0
    
    st.metric(
        "Exposure Score",
        f"{whatif_exposure_calc['exposure_score_1000']:.0f}/1000"
    )

# Detailed breakdown table
st.markdown("#### Detailed Attribute Breakdown")

if new_asset_crit_calc['breakdown']:
    breakdown_df = pd.DataFrame(new_asset_crit_calc['breakdown'])
    
    # Format the dataframe
    display_df = breakdown_df[['field', 'value', 'field_weight', 'value_weightage', 'weighted_score', 'max_possible', 'included']].copy()
    display_df.columns = ['Field', 'Selected Value', 'Field Weight', 'Value Weight', 'Weighted Score', 'Max Possible', 'Included']
    
    # Apply styling to show excluded fields
    def highlight_excluded(row):
        if not row['Included']:
            return ['background-color: #ffebee; opacity: 0.6'] * len(row)
        return [''] * len(row)
    
    st.dataframe(
        display_df.style.apply(highlight_excluded, axis=1),
        hide_index=True,
        width='stretch',
        height=350
    )
    
    # Summary metrics
    summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
    with summary_col1:
        st.metric("Total Weighted Score", f"{new_asset_crit_calc['total_weighted_score']:.1f}")
    with summary_col2:
        st.metric("Maximum Possible", f"{new_asset_crit_calc['total_max_possible']:.1f}")
    with summary_col3:
        ratio = new_asset_crit_calc['total_weighted_score'] / new_asset_crit_calc['total_max_possible'] if new_asset_crit_calc['total_max_possible'] > 0 else 0
        st.metric("Score Ratio", f"{ratio:.3f}")
    with summary_col4:
        included_count = len([b for b in new_asset_crit_calc['breakdown'] if b['included']])
        total_count = len(combined_mappings)
        st.metric("Fields Included", f"{included_count}/{total_count}")

st.markdown("---")

# ---------------------------------------------------
# Vulnerability Score Impact Analysis Section
# ---------------------------------------------------
st.subheader("🔬 Vulnerability Score Impact Analysis")
st.markdown("*See how changes in CVSS and EPSS scores affect the exposure score*")

vuln_col1, vuln_col2 = st.columns(2)

with vuln_col1:
    st.markdown("#### What-If Scores")
    
    score_comparison = pd.DataFrame({
        'Metric': ['CVSS Base Score', 'EPSS Score'],
        'What-If': [
            f"{st.session_state.cvss_base_whatif:.2f}",
            f"{st.session_state.epss_whatif:.4f}"
        ]
    })
    
    st.dataframe(score_comparison, hide_index=True, width='stretch')

with vuln_col2:
    st.markdown("#### Component Impact")
    
    st.metric(
        "Impact Component Change",
        f"{whatif_exposure_calc['impact_base'] * 100:.0f}/1000"
    )
    
    st.metric(
        "Likelihood Component Change",
        f"{current_calc['likelihood_final']*100:.0f}/1000"
    )

st.markdown("---")

# ---------------------------------------------------
# Detailed Calculation Breakdown
# ---------------------------------------------------
st.subheader("🔍 How This Score Was Calculated")

# Show the formula
st.markdown("#### Formula")
st.latex(r"\text{Exposure Score} = \sqrt{\frac{\text{Impact}^2 + \text{Likelihood}^2}{2}} \times 100")

calc_col1, calc_col2 = st.columns(2)

with calc_col1:
    st.markdown("#### 📈 Impact Component")

    with st.expander("View Impact Calculation Details", expanded=False):
        st.write(f"**Base Impact**")
        st.write(f"Asset Criticality: {new_asset_crit_score:.0f}/1000 ")
        st.write(f"CVSS Base Score: {st.session_state.cvss_base_whatif:.2f} ")
        st.write(f"Normalized Impact: {whatif_exposure_calc['impact_base'] * 100:.0f}/1000")
        st.write("No modifiers applied to impact")

        # Show current asset criticality features from what-if selections
        st.write("**Current Asset Criticality Features:**")
        for field_name, selected_value in st.session_state.asset_crit_selections.items():
            pretty_key = field_name.replace('_', ' ').title()
            if isinstance(selected_value, bool):
                selected_value = "Yes" if selected_value else "No"
            
            if field_name in st.session_state.excluded_fields:
                st.write(f"- **{pretty_key}:** ~~{selected_value}~~ (Excluded)")
            else:
                st.write(f"- **{pretty_key}:** {selected_value}")
        st.write(f"Final Impact: **{whatif_exposure_calc['impact_base'] * 100:.0f}/1000**")

with calc_col2:
    st.markdown("#### 📊 Likelihood Component")

    with st.expander("View Likelihood Calculation Details", expanded=False):
        st.write(f"**Step 1: Base Likelihood**")
        st.write(f"EPSS Score: {st.session_state.epss_whatif:.4f}")
        st.write(f"Normalized Likelihood: {current_calc['likelihood_base'] * 100:.0f}/1000")

        st.write(f"\n**Step 2: Apply Modifiers**")
        if current_calc['likelihood_mods_applied']:
            st.write("Applied modifiers:")
            for mod in current_calc['likelihood_mods_applied']:
                st.write(f"  • {mod}")
            st.write(f"Combined multiplier: **{current_calc['likelihood_multiplier']:.2f}x**")
        else:
            st.write("No modifiers applied to likelihood")

        st.write(f"\n**Step 3: Final Likelihood**")
        st.write(
            f"{current_calc['likelihood_base']*100:.0f} × {current_calc['likelihood_multiplier']:.2f} = {current_calc['likelihood_with_mods']*100:.0f}")
        if current_calc['likelihood_with_mods'] > 10:
            st.write(f"Capped at maximum: **{current_calc['likelihood_final']:.2f}/10**")
        else:
            st.write(f"Final Likelihood: **{current_calc['likelihood_final']*100:.0f}/1000**")

# Final calculation
st.markdown("#### 🎯 Final Score Calculation")
st.write(f"RMS = √(({whatif_exposure_calc['impact_base'] * 100:.0f}² + {whatif_exposure_calc['likelihood_final']*100:.0f}²) / 2)")
st.write(
    f"**Final Exposure Score = {whatif_exposure_calc['exposure_score_1000']:.0f}/1000**")

st.markdown("---")

# ---------------------------------------------------
# Visualizations
# ---------------------------------------------------
st.subheader("📈 Visual Analysis")

viz_col1, viz_col2 = st.columns(2)

with viz_col1:
    st.markdown("#### Impact vs Likelihood Breakdown")
    fig1, ax1 = plt.subplots(figsize=(8, 5))

    components = ['Impact', 'Likelihood']
    base_values = [whatif_exposure_calc['impact_base'], whatif_exposure_calc['likelihood_base']]
    final_values = [whatif_exposure_calc['impact_final'], whatif_exposure_calc['likelihood_final']]

    x = np.arange(len(components))
    width = 0.35

    bars1 = ax1.bar(x - width / 2, base_values, width, label='Base (no modifiers)', color='#90caf9', alpha=0.8)
    bars2 = ax1.bar(x + width / 2, final_values, width, label='With modifiers', color='#ef5350', alpha=0.8)

    ax1.set_ylabel('Score (1-10)', fontsize=11)
    ax1.set_title('Impact vs Likelihood Comparison', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(components, fontsize=11)
    ax1.legend(fontsize=10)
    ax1.set_ylim(0, 12)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    ax1.axhline(y=10, color='red', linestyle='--', linewidth=1, alpha=0.5)

    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.15,
                     f'{height:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

    st.pyplot(fig1)

with viz_col2:
    st.markdown("#### Score Contribution")
    fig2, ax2 = plt.subplots(figsize=(8, 5))

    total = whatif_exposure_calc['impact_final'] ** 2 + whatif_exposure_calc['likelihood_final'] ** 2
    impact_contribution = (whatif_exposure_calc['impact_final'] ** 2 / total) * 100
    likelihood_contribution = (whatif_exposure_calc['likelihood_final'] ** 2 / total) * 100

    sizes = [impact_contribution, likelihood_contribution]
    colors = ['#42a5f5', '#ff7043']
    explode = (0.05, 0.05)

    wedges, texts, autotexts = ax2.pie(sizes, explode=explode, labels=['Impact', 'Likelihood'],
                                       colors=colors, autopct='%1.1f%%', shadow=True,
                                       startangle=90, textprops={'fontsize': 11, 'fontweight': 'bold'})

    ax2.axis('equal')
    ax2.set_title('Contribution to Final Score', fontsize=12, fontweight='bold')

    st.pyplot(fig2)

st.markdown("---")

# ---------------------------------------------------
# What-If Scenario Analysis (Modifiers)
# ---------------------------------------------------
st.subheader("🎯 Modifier What-If Analysis")
st.markdown("*See how the score changes with different modifier combinations*")

scenarios = []

# Use current what-if asset criticality and vulnerability scores for scenarios
for mod_key in original_modifiers.keys():
    scenario_mods = st.session_state.modifier_states.copy()
    scenario_mods[mod_key] = not scenario_mods[mod_key]

    scenario_calc = calculate_exposure_score(
        new_asset_crit_score,
        st.session_state.cvss_base_whatif,
        st.session_state.epss_whatif,
        scenario_mods
    )

    action = "Remove" if st.session_state.modifier_states[mod_key] else "Add"
    pretty_name = mod_key.replace("_", " ").title()

    score_diff = scenario_calc['exposure_score_1000'] - whatif_exposure_calc['exposure_score_1000']
    pct_diff = (score_diff / whatif_exposure_calc.get('exposure_score_1000', 0) * 100) if whatif_exposure_calc.get('exposure_score_1000', 0) > 0 else 0

    scenarios.append({
        'Scenario': f'{action} {pretty_name}',
        'New Score': f"{scenario_calc['exposure_score_1000']:.0f}",
        'Change': f"{score_diff:+.0f}",
        'Change %': f"{pct_diff:+.1f}%"
    })

scenarios_df = pd.DataFrame(scenarios)

def color_change(val):
    if '+' in val:
        return 'background-color: #ffcdd2'
    elif '-' in val:
        return 'background-color: #c8e6c9'
    return ''

st.dataframe(
    scenarios_df.style.map(color_change, subset=['Change', 'Change %']),
    width='stretch',
    height=400
)

st.markdown("---")

# ---------------------------------------------------