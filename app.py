import streamlit as st
import json
import numpy as np
import pandas as pd

# Page Configuration
st.set_page_config(
    page_title="Exposure Score Explainability",
    page_icon="🛡️",
    layout="wide"
)

# Define Default Asset Criticality Attribute Mappings
def get_default_asset_criticality_mappings():
    """Default configuration for asset criticality attributes"""
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

# Load JSON data dynamically
@st.cache_data
def load_data():
    with open('sv_ac_high.json') as f:
        return json.load(f)

# Initialize session state
if "asset_crit_config" not in st.session_state:
    st.session_state.asset_crit_config = get_default_asset_criticality_mappings()

# Load data
data = load_data()

# Helper Functions
def normalize_to_10(value, scale=1000):
    """Normalize values from 0-1000 scale to 1-10 scale"""
    return (value / scale) * 10

def calculate_asset_criticality_score(selected_attributes, mappings, excluded_fields):
    """Calculate asset criticality based on selected attributes"""
    total_weighted_score = 0
    total_max_possible = 0
    breakdown = []
    
    for field_name, selected_value in selected_attributes.items():
        if field_name in mappings and field_name not in excluded_fields:
            field_config = mappings[field_name]
            field_weight = field_config['field_weight']
            value_weightage = field_config['values'].get(str(selected_value), 1)
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
    impact_base_norm = normalize_to_10(asset_crit_score + cvss_base_val * 100, scale=2000)
    likelihood_base_norm = normalize_to_10(epss_val * 1000, scale=1000)
    likelihood_with_mods = likelihood_base_norm
    likelihood_mods_applied = []
    likelihood_multiplier = 1.0

    original_modifiers = data.get('modifiers', {})
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

# ====================
# ADMIN CONFIGURATION PAGE
# ====================
def render_admin_page():
    st.title("⚙️ Admin Configuration")
    st.markdown("**Manage Asset Criticality Fields and Weights**")
    st.info("ℹ️ Note: Configuration changes are stored in session memory and will reset when you refresh the page.")
    
    st.markdown("---")
    
    # Admin controls
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("➕ Add New Field", use_container_width=True):
            st.session_state.show_add_field = True
    
    with col2:
        if st.button("🔄 Reset to Defaults", use_container_width=True):
            st.session_state.asset_crit_config = get_default_asset_criticality_mappings()
            st.success("Configuration reset to defaults!")
            st.rerun()
    
    st.markdown("---")
    
    # Add new field dialog
    if st.session_state.get("show_add_field", False):
        with st.expander("➕ Add New Field", expanded=True):
            with st.form("add_field_form"):
                st.markdown("#### Create New Asset Criticality Field")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    new_field_name = st.text_input(
                        "Field Name",
                        placeholder="e.g., Data Sensitivity Level"
                    )
                
                with col2:
                    new_field_weight = st.number_input(
                        "Field Weight",
                        min_value=1,
                        max_value=10,
                        value=5
                    )
                
                st.markdown("#### Field Values")
                st.markdown("*Enter values and their weights (comma-separated)*")
                st.markdown("**Format:** `value1:weight1, value2:weight2, ...`")
                st.markdown("**Example:** `High:10, Medium:5, Low:1, null:1`")
                
                values_text = st.text_area(
                    "Values",
                    placeholder="High:10, Medium:5, Low:1, null:1",
                    height=100
                )
                
                col1, col2 = st.columns([1, 5])
                
                with col1:
                    submit = st.form_submit_button("Create Field", type="primary")
                
                with col2:
                    cancel = st.form_submit_button("Cancel")
                
                if cancel:
                    st.session_state.show_add_field = False
                    st.rerun()
                
                if submit:
                    if not new_field_name or not values_text:
                        st.error("Please fill in all fields")
                    elif new_field_name in st.session_state.asset_crit_config:
                        st.error("Field name already exists")
                    else:
                        try:
                            # Parse values
                            values_dict = {}
                            for pair in values_text.split(','):
                                pair = pair.strip()
                                if ':' in pair:
                                    val, weight = pair.split(':', 1)
                                    values_dict[val.strip()] = float(weight.strip())
                            
                            if len(values_dict) < 2:
                                st.error("Please add at least 2 values")
                            else:
                                # Add new field
                                st.session_state.asset_crit_config[new_field_name] = {
                                    "field_weight": new_field_weight,
                                    "values": values_dict
                                }
                                
                                st.session_state.show_add_field = False
                                st.success(f"Field '{new_field_name}' created successfully!")
                                st.rerun()
                        
                        except Exception as e:
                            st.error(f"Error parsing values: {e}")
    
    # Display existing fields
    st.markdown("### 📋 Current Fields Configuration")
    
    for field_name in list(st.session_state.asset_crit_config.keys()):
        field_config = st.session_state.asset_crit_config[field_name]
        
        with st.expander(f"**{field_name}** (Weight: {field_config['field_weight']})", expanded=False):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Edit field weight
                new_weight = st.number_input(
                    "Field Weight",
                    min_value=1,
                    max_value=10,
                    value=field_config['field_weight'],
                    key=f"weight_{field_name}"
                )
                
                if new_weight != field_config['field_weight']:
                    st.session_state.asset_crit_config[field_name]['field_weight'] = new_weight
                    st.info("⚠️ Weight updated in session memory")
            
            with col2:
                if st.button("🗑️ Delete Field", key=f"delete_{field_name}"):
                    del st.session_state.asset_crit_config[field_name]
                    st.success(f"Field '{field_name}' deleted!")
                    st.rerun()
            
            st.markdown("#### Field Values")
            
            # Display values
            values_df = pd.DataFrame([
                {"Value": val, "Weight": weight}
                for val, weight in field_config['values'].items()
            ])
            
            st.dataframe(values_df, hide_index=True, use_container_width=True)
            
            # Two tabs: one for editing existing, one for adding new
            tab1, tab2 = st.tabs(["✏️ Edit Existing Value", "➕ Add New Value"])
            
            with tab1:
                # Edit existing values with dropdown
                st.markdown("**Select and Edit Existing Value**")
                
                existing_values = list(field_config['values'].keys())
                if existing_values:
                    selected_value_to_edit = st.selectbox(
                        "Select Value to Edit",
                        options=existing_values,
                        key=f"select_edit_{field_name}"
                    )
                    
                    current_weight = field_config['values'][selected_value_to_edit]
                    
                    with st.form(f"edit_existing_value_{field_name}"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.markdown("**Value Name**")
                            st.info(f" {selected_value_to_edit}")
                        
                        with col2:
                            new_weight = st.number_input(
                                "New Weight",
                                min_value=0.1,
                                max_value=10.0,
                                value=float(current_weight),
                                step=0.1,
                                key=f"edit_weight_{field_name}"
                            )
                        
                        if st.form_submit_button("Update Weight", type="primary"):
                            st.session_state.asset_crit_config[field_name]['values'][selected_value_to_edit] = new_weight
                            st.success(f"Value '{selected_value_to_edit}' updated to weight {new_weight}!")
                            st.rerun()
                else:
                    st.info("No values to edit. Add values in the 'Add New Value' tab.")
            
            with tab2:
                # Add new values
                with st.form(f"add_new_value_{field_name}"):
                    st.markdown("**Add New Value**")
                    
                    existing_values_str = ", ".join(field_config['values'].keys())
                    st.caption(f"Existing values: {existing_values_str}")
                    
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        new_value_name = st.text_input("Value Name", key=f"new_val_name_{field_name}", placeholder="Enter new value name")
                    
                    with col2:
                        new_value_weight = st.number_input(
                            "Weight",
                            min_value=0.1,
                            max_value=10.0,
                            value=5.0,
                            step=0.1,
                            key=f"new_val_weight_{field_name}"
                        )
                    
                    with col3:
                        st.markdown("<br>", unsafe_allow_html=True)
                        add_new = st.form_submit_button("Add Value")
                    
                    if add_new and new_value_name:
                        # Check for exact match
                        if new_value_name in field_config['values']:
                            st.error(f"❌ Value '{new_value_name}' already exists! Use the 'Edit Existing Value' tab to modify it.")
                        else:
                            # Check for case-insensitive duplicates
                            existing_keys = list(field_config['values'].keys())
                            matching_key = None
                            
                            for existing_key in existing_keys:
                                if existing_key.lower() == new_value_name.lower():
                                    matching_key = existing_key
                                    break
                            
                            if matching_key:
                                st.error(f"❌ A similar value '{matching_key}' already exists with different case. Please use exact case or choose a different name.")
                            else:
                                st.session_state.asset_crit_config[field_name]['values'][new_value_name] = new_value_weight
                                st.success(f"✅ Value '{new_value_name}' added successfully!")
                                st.rerun()
            
            # Delete individual values
            st.markdown("**Delete Values**")
            cols = st.columns(4)
            for idx, (val_name, val_weight) in enumerate(field_config['values'].items()):
                col_idx = idx % 4
                with cols[col_idx]:
                    if st.button(f"❌ {val_name}", key=f"del_val_{field_name}_{val_name}"):
                        if len(field_config['values']) > 2:
                            del st.session_state.asset_crit_config[field_name]['values'][val_name]
                            st.success(f"Value '{val_name}' deleted!")
                            st.rerun()
                        else:
                            st.error("Cannot delete - field must have at least 2 values")

# ====================
# USER INTERFACE PAGE
# ====================
def render_user_page():
    # Extract core scoring parameters
    if 'calculated_scores' in data and 'impact_base' in data['calculated_scores'] and isinstance(data['calculated_scores']['impact_base'], dict):
        asset_crit = data.get('calculated_scores', {}).get('impact_base', {}).get('asset_criticality', {}).get('overall_asset_criticality', 0)
    else:
        asset_crit = data.get('asset_criticality', {}).get('overall_asset_criticality', 0)

    cvss_base = data.get('cvss_base_score', 0)
    epss = data.get('epss_score', 0)
    original_modifiers = data.get('modifiers', {})

    # Initialize session state
    if "modifier_states" not in st.session_state:
        st.session_state.modifier_states = {
            mod_key: mod_value.get("applies", False)
            for mod_key, mod_value in original_modifiers.items()
        }

    if "asset_crit_selections" not in st.session_state:
        st.session_state.asset_crit_selections = {}
        for field_name, field_config in st.session_state.asset_crit_config.items():
            values_list = list(field_config['values'].keys())
            if values_list:
                st.session_state.asset_crit_selections[field_name] = values_list[0]

    if "excluded_fields" not in st.session_state:
        st.session_state.excluded_fields = set()

    if "cvss_base_whatif" not in st.session_state:
        st.session_state.cvss_base_whatif = cvss_base
    if "epss_whatif" not in st.session_state:
        st.session_state.epss_whatif = epss

    if "user_weight_overrides" not in st.session_state:
        st.session_state.user_weight_overrides = {}

    st.title("🛡️ Exposure Score Explainability Dashboard")
    st.markdown("**Understand how your exposure score is calculated and explore what-if scenarios**")

    # Sidebar controls
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

    # Modifier Controls
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚡ Likelihood Modifiers")
    for mod_key, mod_value in original_modifiers.items():
        pretty_name = mod_key.replace("_", " ").title()
        description = mod_value.get("description", "")
        multiplier_config = mod_value.get("multiplier", {})

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

    # Calculate scores
    current_calc = calculate_exposure_score(
        asset_crit,
        st.session_state.cvss_base_whatif,
        st.session_state.epss_whatif,
        st.session_state.modifier_states
    )

    # Asset Criticality What-If Section
    st.subheader("🏢 Asset Criticality What-If Analysis")
    st.markdown("*Explore how different asset attributes affect the criticality score and overall exposure*")

    whatif_col1, whatif_col2 = st.columns([2, 1])

    with whatif_col1:
        st.markdown("#### Configure Asset Attributes")
        
        # User weight override option
        st.markdown("##### 🎚️ Adjust Field Weights")
        
        # Weight adjustment expander
        with st.expander("✏️ Override Field Weights", expanded=False):
            st.markdown("*Adjust weights for individual fields (affects calculation)*")
            
            weight_cols = st.columns(3)
            
            for idx, field_name in enumerate(st.session_state.asset_crit_config.keys()):
                col_idx = idx % 3
                with weight_cols[col_idx]:
                    default_weight = st.session_state.asset_crit_config[field_name]['field_weight']
                    current_override = st.session_state.user_weight_overrides.get(field_name, default_weight)
                    
                    new_weight = st.number_input(
                        f"{field_name}",
                        min_value=1,
                        max_value=10,
                        value=int(current_override),
                        key=f"user_weight_{field_name}",
                        help=f"Default: {default_weight}"
                    )
                    
                    if new_weight != default_weight:
                        st.session_state.user_weight_overrides[field_name] = new_weight
                    elif field_name in st.session_state.user_weight_overrides:
                        del st.session_state.user_weight_overrides[field_name]
        
        # Apply weight overrides for calculation
        working_config = {}
        for field_name, field_config in st.session_state.asset_crit_config.items():
            working_config[field_name] = {
                'field_weight': field_config['field_weight'],
                'values': field_config['values'].copy()
            }
            if field_name in st.session_state.user_weight_overrides:
                working_config[field_name]['field_weight'] = st.session_state.user_weight_overrides[field_name]
        
        # st.markdown("---")
        
        # Create attribute selection grid
        attr_cols = st.columns(3)
        
        for idx, (field_name, field_config) in enumerate(working_config.items()):
            col_idx = idx % 3
            with attr_cols[col_idx]:
                is_excluded = field_name in st.session_state.excluded_fields
                
                # Show weight info
                display_weight = working_config[field_name]['field_weight']
                weight_indicator = " 🎚️" if field_name in st.session_state.user_weight_overrides else ""
                
                checkbox_label = f"{field_name}{weight_indicator} (Weight: {display_weight})"
                is_included = st.checkbox(
                    checkbox_label,
                    value=not is_excluded,
                    key=f"include_{field_name}",
                    help=f"Field Weight: {display_weight}"
                )
                
                if not is_included:
                    st.session_state.excluded_fields.add(field_name)
                else:
                    st.session_state.excluded_fields.discard(field_name)
                
                options = list(field_config['values'].keys())
                
                if not options:
                    st.warning(f"No values defined for {field_name}")
                    continue
                
                if field_name not in st.session_state.asset_crit_selections:
                    st.session_state.asset_crit_selections[field_name] = options[0]
                
                current_value = st.session_state.asset_crit_selections.get(field_name, options[0])
                
                try:
                    current_idx = options.index(current_value)
                except ValueError:
                    current_idx = 0
                    st.session_state.asset_crit_selections[field_name] = options[0]
                
                label = "Value:" if is_included else "Value (Excluded):"
                
                selected = st.selectbox(
                    label,
                    options=options,
                    index=current_idx,
                    key=f"asset_attr_{field_name}",
                    help=f"Select value for {field_name}",
                    disabled=not is_included
                )
                
                st.session_state.asset_crit_selections[field_name] = selected
                st.markdown("---")

    # Calculate new asset criticality with overridden weights
    new_asset_crit_calc = calculate_asset_criticality_score(
        st.session_state.asset_crit_selections,
        working_config,
        st.session_state.excluded_fields
    )
    new_asset_crit_score = new_asset_crit_calc['score']

    whatif_exposure_calc = calculate_exposure_score(
        new_asset_crit_score,
        st.session_state.cvss_base_whatif,
        st.session_state.epss_whatif,
        st.session_state.modifier_states
    )

    with whatif_col2:
        st.markdown("#### Impact Summary")
        
        st.metric(
            "Asset Criticality",
            f"{new_asset_crit_score:.0f}/1000"
        )
        
        st.metric(
            "Exposure Score",
            f"{whatif_exposure_calc['exposure_score_1000']:.0f}/1000"
        )

    # Detailed breakdown
    st.markdown("#### Detailed Attribute Breakdown")

    if new_asset_crit_calc['breakdown']:
        breakdown_df = pd.DataFrame(new_asset_crit_calc['breakdown'])
        
        display_df = breakdown_df[['field', 'value', 'field_weight', 'value_weightage', 'weighted_score', 'max_possible', 'included']].copy()
        display_df.columns = ['Field', 'Selected Value', 'Field Weight', 'Value Weight', 'Weighted Score', 'Max Possible', 'Included']
        
        def highlight_excluded(row):
            if not row['Included']:
                return ['background-color: #ffebee; opacity: 0.6'] * len(row)
            return [''] * len(row)
        
        st.dataframe(
            display_df.style.apply(highlight_excluded, axis=1),
            hide_index=True,
            use_container_width=True,
            height=350
        )
        
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
            total_count = len(working_config)
            st.metric("Fields Included", f"{included_count}/{total_count}")

    st.markdown("---")

    # Detailed Calculation Breakdown
    st.subheader("🔍 How This Score Was Calculated")

    st.markdown("#### Formula")
    st.latex(r"\text{Exposure Score} = \sqrt{\frac{\text{Impact}^2 + \text{Likelihood}^2}{2}} \times 100")

    calc_col1, calc_col2 = st.columns(2)

    with calc_col1:
        st.markdown("#### 📈 Impact Component")

        with st.expander("View Impact Calculation Details", expanded=False):
            st.write("**Base Impact**")
            st.write(f"Asset Criticality: {new_asset_crit_score:.0f}/1000")
            st.write(f"CVSS Base Score: {st.session_state.cvss_base_whatif:.2f}")
            st.write(f"Normalized Impact: {whatif_exposure_calc['impact_base'] * 100:.0f}/1000")
            st.write("No modifiers applied to impact")

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
            st.write("**Step 1: Base Likelihood**")
            st.write(f"EPSS Score: {st.session_state.epss_whatif:.4f}")
            st.write(f"Normalized Likelihood: {current_calc['likelihood_base'] * 100:.0f}/1000")

            st.write("\n**Step 2: Apply Modifiers**")
            if current_calc['likelihood_mods_applied']:
                st.write("Applied modifiers:")
                for mod in current_calc['likelihood_mods_applied']:
                    st.write(f"  • {mod}")
                st.write(f"Combined multiplier: **{current_calc['likelihood_multiplier']:.2f}x**")
            else:
                st.write("No modifiers applied to likelihood")

            st.write("\n**Step 3: Final Likelihood**")
            st.write(f"{current_calc['likelihood_base']*100:.0f} × {current_calc['likelihood_multiplier']:.2f} = {current_calc['likelihood_with_mods']*100:.0f}")
            if current_calc['likelihood_with_mods'] > 10:
                st.write(f"Capped at maximum: **{current_calc['likelihood_final']:.2f}/10**")
            else:
                st.write(f"Final Likelihood: **{current_calc['likelihood_final']*100:.0f}/1000**")

    # Final calculation
    st.markdown("#### 🎯 Final Score Calculation")
    st.write(f"RMS = √(({whatif_exposure_calc['impact_base'] * 100:.0f}² + {whatif_exposure_calc['likelihood_final']*100:.0f}²) / 2)")
    st.write(f"**Final Exposure Score = {whatif_exposure_calc['exposure_score_1000']:.0f}/1000**")

    st.markdown("---")

    # What-If Scenario Analysis
    st.subheader("🎯 Modifier What-If Analysis")
    st.markdown("*See how the score changes with different modifier combinations*")

    scenarios = []

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
        if '+' in str(val):
            return 'background-color: #ffcdd2'
        elif '-' in str(val):
            return 'background-color: #c8e6c9'
        return ''

    st.dataframe(
        scenarios_df.style.map(color_change, subset=['Change', 'Change %']),
        use_container_width=True,
        height=400
    )

# ====================
# MAIN APP NAVIGATION
# ====================

# Sidebar navigation
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🔀 Navigation")
    
    page = st.radio(
        "Select Page",
        ["User Dashboard", "Admin Configuration"],
        key="page_selector"
    )

# Render appropriate page
if page == "Admin Configuration":
    render_admin_page()
else:
    render_user_page()