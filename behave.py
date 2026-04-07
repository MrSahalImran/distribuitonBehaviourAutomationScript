import argparse
import json

import boto3
from botocore.exceptions import ClientError

# Create a CloudFront client once and reuse it for all API calls in this script.
cf = boto3.client("cloudfront")

# These keys are mandatory inside behavior config for both single and multi-path modes.
REQUIRED_BEHAVIOR_KEYS = [
    "target_origin_id",
    "viewer_protocol_policy",
    "cache_policy_id",
    "origin_request_policy_id",
    "response_headers_policy_id",
]
# Predefined HTTP method presets for easy selection.
ALLOWED_METHOD_PRESETS = {
    1: {  # Read-only methods
        "items": ["GET", "HEAD"],
        "cached": ["GET", "HEAD"],
        "description": "GET, HEAD (read-only)",
    },
    2: {  # Read with OPTIONS
        "items": ["GET", "HEAD", "OPTIONS"],
        "cached": ["GET", "HEAD"],
        "description": "GET, HEAD, OPTIONS (read with preflight)",
    },
    3: {  # All methods (read + write)
        "items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
        "cached": ["GET", "HEAD"],
        "description": "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE (all methods)",
    },
}

# Viewer Protocol Policy presets for easy selection.
VIEWER_PROTOCOL_POLICIES = {
    1: {
        "policy": "allow-all",
        "description": "Allow HTTP and HTTPS",
    },
    2: {
        "policy": "redirect-to-https",
        "description": "Redirect HTTP to HTTPS",
    },
    3: {
        "policy": "https-only",
        "description": "HTTPS only",
    },
}


# -----------------------------
# LIST DISTRIBUTIONS
# -----------------------------
def list_distributions():
    # Fetch distributions visible to the configured AWS credentials.
    res = cf.list_distributions()
    # Safely read the list even when there are no distributions.
    items = res.get("DistributionList", {}).get("Items", [])

    # Print distributions so the user can pick one in interactive mode.
    print("\nAvailable Distributions:\n")
    # Print 1-based index with distribution ID and domain name.
    for i, d in enumerate(items):
        print(f"{i+1}. {d['Id']} | {d['DomainName']}")

    # Return raw items for selection logic.
    return items


def load_json_config(file_path):
    # Open and parse config JSON from disk.
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Validate root type to avoid downstream key/type errors.
    if not isinstance(data, dict):
        raise ValueError("Config file must contain a JSON object.")
    # Return validated config object.
    return data


# -----------------------------
# SELECT DISTRIBUTION
# -----------------------------
def select_distribution(dists):
    # Read selection as 1-based index and convert it to 0-based list index.
    choice = int(input("\nSelect distribution number: ")) - 1
    # Return selected distribution ID.
    return dists[choice]["Id"]


# -----------------------------
# GET CONFIG
# -----------------------------
def get_config(dist_id):
    # Get mutable distribution config plus ETag required for update calls.
    res = cf.get_distribution_config(Id=dist_id)
    return res["DistributionConfig"], res["ETag"]


def get_allowed_methods(method_preset_option):
    # Get allowed methods structure based on preset choice (1, 2, or 3).
    # Default to preset 1 (read-only) if not specified.
    preset = ALLOWED_METHOD_PRESETS.get(method_preset_option, ALLOWED_METHOD_PRESETS[1])
    return {
        "Quantity": len(preset["items"]),
        "Items": preset["items"],
        "CachedMethods": {"Quantity": len(preset["cached"]), "Items": preset["cached"]},
    }


def select_allowed_methods():
    # Display method preset options and return user's choice.
    print("\nAllowed HTTP Methods:")
    for preset_id, preset_config in ALLOWED_METHOD_PRESETS.items():
        print(f"{preset_id}. {preset_config['description']}")
    choice = int(input("Select allowed methods (1-3): "))
    if choice not in ALLOWED_METHOD_PRESETS:
        raise ValueError(f"Invalid choice. Must be 1, 2, or 3.")
    return choice


def select_viewer_protocol_policy():
    # Display viewer protocol policy options and return user's choice.
    print("\nViewer Protocol Policy:")
    for policy_id, policy_config in VIEWER_PROTOCOL_POLICIES.items():
        print(f"{policy_id}. {policy_config['description']}")
    choice = int(input("Select viewer protocol policy (1-3): "))
    if choice not in VIEWER_PROTOCOL_POLICIES:
        raise ValueError(f"Invalid choice. Must be 1, 2, or 3.")
    return VIEWER_PROTOCOL_POLICIES[choice]["policy"]


def build_behavior(values):
    # Build one CloudFront cache behavior payload from normalized values.
    # Get allowed methods from preset option (default to 1: read-only).
    method_preset = values.get("allowed_methods", 1)
    return {
        # The path pattern this behavior should match, for example /images/*.
        "PathPattern": values["path_pattern"],
        # Origin or origin group ID to route matching requests to.
        "TargetOriginId": values["target_origin_id"],
        # Viewer protocol policy controls HTTP/HTTPS handling.
        "ViewerProtocolPolicy": values["viewer_protocol_policy"],
        # Cache policy controls TTL and cache key behavior.
        "CachePolicyId": values["cache_policy_id"],
        # Origin request policy controls headers/cookies/query forwarding.
        "OriginRequestPolicyId": values["origin_request_policy_id"],
        # Response headers policy controls security/CORS headers.
        "ResponseHeadersPolicyId": values["response_headers_policy_id"],
        # Use configurable HTTP methods based on preset selection.
        "AllowedMethods": get_allowed_methods(method_preset),
        # Enable compression unless explicitly disabled in config.
        "Compress": values.get("compress", True),
        # Keep smooth streaming disabled by default.
        "SmoothStreaming": False,
        # Explicitly set empty lambda/function associations.
        "LambdaFunctionAssociations": {"Quantity": 0},
        "FunctionAssociations": {"Quantity": 0},
        # Leave field-level encryption unset.
        "FieldLevelEncryptionId": "",
        # Disable trusted signer and key group restrictions.
        "TrustedSigners": {"Enabled": False, "Quantity": 0},
        "TrustedKeyGroups": {"Enabled": False, "Quantity": 0},
    }


def add_behavior_to_distribution_config(distribution_config, new_behavior):
    # If this is the first custom behavior, initialize CacheBehaviors structure.
    if distribution_config.get("CacheBehaviors", {}).get("Quantity", 0) == 0:
        distribution_config["CacheBehaviors"] = {"Quantity": 1, "Items": [new_behavior]}
    else:
        # Otherwise append to the existing behavior list and increment quantity.
        distribution_config["CacheBehaviors"]["Items"].append(new_behavior)
        distribution_config["CacheBehaviors"]["Quantity"] += 1

    # Return mutated distribution config for chaining.
    return distribution_config


def validate_behavior_input(behavior_values):
    # Check presence of required common fields.
    missing = [k for k in REQUIRED_BEHAVIOR_KEYS if k not in behavior_values]
    if missing:
        raise ValueError(f"Missing behavior keys in config: {missing}")

    # Support either one path via path_pattern or many paths via paths array.
    has_single_path = "path_pattern" in behavior_values
    has_paths_array = "paths" in behavior_values
    if not has_single_path and not has_paths_array:
        raise ValueError(
            "Config behavior must contain either 'path_pattern' or 'paths'."
        )

    # Validate paths array when provided.
    if has_paths_array:
        if (
            not isinstance(behavior_values["paths"], list)
            or not behavior_values["paths"]
        ):
            raise ValueError("'paths' must be a non-empty array.")
        # Every path must be a non-empty string.
        if not all(
            isinstance(path, str) and path.strip() for path in behavior_values["paths"]
        ):
            raise ValueError("All entries in 'paths' must be non-empty strings.")


def get_path_patterns(behavior_values):
    # Prefer array mode when paths is present.
    if "paths" in behavior_values:
        return behavior_values["paths"]
    # Fallback to legacy single-path mode.
    return [behavior_values["path_pattern"]]


def parse_space_separated_paths(input_string):
    # Parse space-separated paths from user input and return as list.
    # Example: "/images/* /api/* /static/*" becomes ["/images/*", "/api/*", "/static/*"]
    paths = input_string.strip().split()
    # Filter out empty strings from multiple spaces.
    return [p for p in paths if p]


def path_exists_in_config(distribution_config, path_pattern):
    # Check if this path pattern already exists in any cache behavior.
    cache_behaviors = distribution_config.get("CacheBehaviors", {}).get("Items", [])
    # Return True if any existing behavior matches this path pattern.
    return any(b.get("PathPattern") == path_pattern for b in cache_behaviors)


# -----------------------------
# LIST ORIGINS
# -----------------------------
def list_origins(config):
    # Print origin IDs from the current distribution config.
    print("\nAvailable Origins:\n")
    for o in config["Origins"]["Items"]:
        print(f"- {o['Id']}")


def select_origin(config):
    # Display available origins with numeric options and return user's choice.
    origins = config["Origins"]["Items"]
    print("\nAvailable Origins:\n")
    for i, o in enumerate(origins):
        print(f"{i+1}. {o['Id']}")

    choice = int(input("Select Target Origin ID (1-{0}): ".format(len(origins)))) - 1
    if choice < 0 or choice >= len(origins):
        raise ValueError(f"Invalid choice. Must be 1 to {len(origins)}.")
    return origins[choice]["Id"]


# -----------------------------
# LIST POLICIES
# -----------------------------
def list_cache_policies():
    # List managed cache policies so user can select one interactively.
    res = cf.list_cache_policies(Type="managed")
    items = res["CachePolicyList"]["Items"]

    print("\nCache Policies:\n")
    for i, p in enumerate(items):
        print(
            f"{i+1}. {p['CachePolicy']['Id']} | {p['CachePolicy']['CachePolicyConfig']['Name']}"
        )

    return items


def list_origin_request_policies():
    # List managed origin request policies for interactive selection.
    res = cf.list_origin_request_policies(Type="managed")
    items = res["OriginRequestPolicyList"]["Items"]

    print("\nOrigin Request Policies:\n")
    for i, p in enumerate(items):
        print(
            f"{i+1}. {p['OriginRequestPolicy']['Id']} | {p['OriginRequestPolicy']['OriginRequestPolicyConfig']['Name']}"
        )

    return items


def list_response_headers_policies():
    # List managed response header policies for interactive selection.
    res = cf.list_response_headers_policies(Type="managed")
    items = res["ResponseHeadersPolicyList"]["Items"]

    print("\nResponse Headers Policies:\n")
    for i, p in enumerate(items):
        print(
            f"{i+1}. {p['ResponseHeadersPolicy']['Id']} | {p['ResponseHeadersPolicy']['ResponseHeadersPolicyConfig']['Name']}"
        )

    return items


# -----------------------------
# CREATE BEHAVIOR
# -----------------------------
def create_behavior(config):

    # Collect behavior details from console prompts.
    print("\n--- Enter Behavior Details ---")

    # Ask for path patterns - can be single or space-separated multiple paths.
    path_input = input(
        "Path Pattern(s) - space-separated (e.g. /images/* /api/* /static/*): "
    )
    # Parse space-separated paths into list.
    paths = parse_space_separated_paths(path_input)
    if not paths:
        raise ValueError("At least one path pattern is required.")

    # Show origins to help user enter a valid target origin ID using numeric selection.
    target_origin_id = select_origin(config)

    # Ask how HTTP viewer requests should be handled using numeric selection.
    protocol = select_viewer_protocol_policy()

    # Let user select which HTTP methods are allowed.
    allowed_methods = select_allowed_methods()

    # Policies
    cache_policies = list_cache_policies()
    # Convert selected 1-based index to list index.
    cp_choice = int(input("Select Cache Policy: ")) - 1
    cache_policy_id = cache_policies[cp_choice]["CachePolicy"]["Id"]

    origin_req_policies = list_origin_request_policies()
    # Convert selected 1-based index to list index.
    orp_choice = int(input("Select Origin Request Policy: ")) - 1
    origin_request_policy_id = origin_req_policies[orp_choice]["OriginRequestPolicy"][
        "Id"
    ]

    resp_policies = list_response_headers_policies()
    # Convert selected 1-based index to list index.
    rp_choice = int(input("Select Response Headers Policy: ")) - 1
    response_headers_policy_id = resp_policies[rp_choice]["ResponseHeadersPolicy"]["Id"]

    # Build and add one behavior per input path.
    updated_config = config
    successfully_added = []
    skipped_duplicates = []

    for path_pattern in paths:
        # Check if this path pattern already exists in the distribution.
        if path_exists_in_config(updated_config, path_pattern):
            # Skip this path to avoid duplicate path pattern error.
            print(f"⊘ Skipping path '{path_pattern}' - already exists in distribution.")
            skipped_duplicates.append(path_pattern)
            continue

        # Build one behavior object from collected input.
        new_behavior = build_behavior(
            {
                "path_pattern": path_pattern,
                "target_origin_id": target_origin_id,
                "viewer_protocol_policy": protocol,
                "cache_policy_id": cache_policy_id,
                "origin_request_policy_id": origin_request_policy_id,
                "response_headers_policy_id": response_headers_policy_id,
                "compress": True,
                "allowed_methods": allowed_methods,
            }
        )

        # Attach new behavior and increment count.
        updated_config = add_behavior_to_distribution_config(
            updated_config, new_behavior
        )
        successfully_added.append(path_pattern)

    # Report results
    if skipped_duplicates:
        print(
            f"\n⊘ Skipped {len(skipped_duplicates)} duplicate path(s) (already exist)"
        )
    if not successfully_added:
        raise ValueError(
            "All paths already exist in distribution. No new behaviors to add."
        )

    # Return tuple: updated config and list of successfully added paths
    return updated_config, successfully_added


def update_distribution_from_json(config_file_path):
    # Load non-interactive input from JSON file passed via --config.
    file_config = load_json_config(config_file_path)

    # Validate top-level config keys.
    if "distribution_id" not in file_config:
        raise ValueError("Config must contain 'distribution_id'.")
    if "behavior" not in file_config or not isinstance(file_config["behavior"], dict):
        raise ValueError("Config must contain a 'behavior' object.")

    # Extract target distribution and behavior values.
    dist_id = file_config["distribution_id"]
    behavior_values = file_config["behavior"]
    # Validate behavior schema before making API calls.
    validate_behavior_input(behavior_values)

    # Fetch current distribution config and ETag for conditional update.
    distribution_config, etag = get_config(dist_id)

    # Track which paths were successfully added (not skipped).
    successfully_added_paths = []
    # Track which paths were skipped because they already exist.
    skipped_paths = []

    # Start with current config, then add one behavior per configured path.
    updated_distribution_config = distribution_config
    for path_pattern in get_path_patterns(behavior_values):
        # Check if this path pattern already exists in the distribution.
        if path_exists_in_config(updated_distribution_config, path_pattern):
            # Skip this path to avoid duplicate path pattern error.
            print(f"Skipping path '{path_pattern}' - already exists in distribution.")
            skipped_paths.append(path_pattern)
            continue

        # Build behavior with same policy/origin values for each path.
        new_behavior = build_behavior(
            {
                "path_pattern": path_pattern,
                "target_origin_id": behavior_values["target_origin_id"],
                "viewer_protocol_policy": behavior_values["viewer_protocol_policy"],
                "cache_policy_id": behavior_values["cache_policy_id"],
                "origin_request_policy_id": behavior_values["origin_request_policy_id"],
                "response_headers_policy_id": behavior_values[
                    "response_headers_policy_id"
                ],
                "compress": behavior_values.get("compress", True),
                "allowed_methods": behavior_values.get("allowed_methods", 1),
            }
        )
        # Add behavior into CacheBehaviors.
        updated_distribution_config = add_behavior_to_distribution_config(
            updated_distribution_config, new_behavior
        )
        # Track this path as successfully added.
        successfully_added_paths.append(path_pattern)

    # Submit one distribution update containing all added behaviors.
    update_distribution(
        dist_id, updated_distribution_config, etag, successfully_added_paths
    )


# -----------------------------
# UPDATE DISTRIBUTION
# -----------------------------
def update_distribution(dist_id, config, etag, successfully_added_paths=None):
    # Update CloudFront distribution using ETag-based optimistic locking.
    res = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)

    # Print summary output after update request is accepted.
    print("\n✓ Behavior(s) added successfully!")
    # Show which paths were added if provided.
    if successfully_added_paths:
        print(f"\nSuccessfully added {len(successfully_added_paths)} behavior(s):")
        for path in successfully_added_paths:
            print(f"  - {path}")
    print(f"\nDistribution Status: {res['Distribution']['Status']}")
    print(f"Domain: {res['Distribution']['DomainName']}")


# -----------------------------
# MAIN
# -----------------------------
def main():
    # Parse command-line arguments for interactive/non-interactive modes.
    parser = argparse.ArgumentParser(
        description="Add CloudFront cache behavior interactively or from JSON config"
    )
    parser.add_argument(
        "--config",
        help="Path to config.json for non-interactive mode",
    )
    args = parser.parse_args()

    # Catch common validation and AWS SDK errors to print cleaner messages.
    try:
        # Non-interactive mode: read behavior from config JSON.
        if args.config:
            update_distribution_from_json(args.config)
            return

        # Interactive mode: choose distribution and enter behavior values manually.
        dists = list_distributions()
        dist_id = select_distribution(dists)

        # Load selected distribution config.
        config, etag = get_config(dist_id)

        # Build and append one behavior from user prompts.
        updated_config, successfully_added = create_behavior(config)

        # Submit update request with tracking info.
        update_distribution(dist_id, updated_config, etag, successfully_added)
    except (ValueError, KeyError, ClientError) as exc:
        # Print concise error details.
        print(f"Error: {exc}")


if __name__ == "__main__":
    # Execute entry point when script is run directly.
    main()
