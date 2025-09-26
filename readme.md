# myldap

A user-friendly LDAP enumeration tool that simplifies common LDAP queries and discovery tasks.

## About

While `ldapsearch` is an amazing tool (props to the developers!), it can feel a bit finicky and the syntax is hard to remember sometimes (probably my fault). This tool aims to provide a more intuitive interface for common LDAP enumeration tasks with sensible defaults and human-readable output formatting.

## Features

- **Naming Context Discovery**: Automatically discover available naming contexts on an LDAP server
- **Domain Enumeration**: Search for users, groups, or all objects within a domain
- **Detailed Object Information**: Get comprehensive object attributes (users, groups, computers, etc.) with proper binary data formatting
- **Flexible Authentication**: Support for both anonymous and authenticated binds
- **Custom Filters**: Use custom LDAP filters for specific queries
- **Smart Binary Handling**: Proper formatting for GUIDs, SIDs, and other binary attributes
- **User-Friendly Output**: Clean, organized output with helpful status messages
- **Secure Connection**: Tries LDAPS (port 636) first, falls back to LDAP (port 389) if needed

## Usage

### Discover Naming Contexts
Find all available naming contexts on an LDAP server:
```bash
python3 myldap.py -s <server_ip> --naming-contexts
```

With authentication:
```bash
python3 myldap.py -s <server_ip> -u <username> -p <password> -d <domain> --naming-contexts
```

### Enumerate a Naming Context
Enumerate all objects within a specific naming context:
```bash
python3 myldap.py -s <server_ip> --enumerate "DC=example,DC=com"
```

With custom filter:
```bash
python3 myldap.py -s <server_ip> --enumerate "DC=example,DC=com" --filter "(objectClass=user)"
```

### Get Detailed Object Information
Retrieve all attributes for a specific object DN (user, group, computer, etc.) - note: use the full DN path:
```bash
python3 myldap.py -s <server_ip> --get-object "CN=John Doe,OU=Users,OU=UK,DC=domain,DC=local"
```

With authentication:
```bash
python3 myldap.py -s <server_ip> -u <username> -p <password> -d <domain> --get-object "CN=John Doe,OU=Users,OU=UK,DC=domain,DC=local"
```

**Tip**: If you don't know the exact DN, first search for the object to find the correct path:
```bash
python3 myldap.py -s <server_ip> -d <domain> --enumerate "DC=domain,DC=local" --filter "(cn=John Doe)"
```

### Domain-Based Searches
Search for users in a domain:
```bash
python3 myldap.py -s <server_ip> -d example.com -l users
```

Search for a specific user:
```bash
python3 myldap.py -s <server_ip> -d example.com --search administrator
```

Search for groups in a domain:
```bash
python3 myldap.py -s <server_ip> -d example.com -l groups
```

Search for all objects in a domain:
```bash
python3 myldap.py -s <server_ip> -d example.com -l all
```

## Command Line Options

- `-s, --server`: LDAP server IP or hostname (required)
- `-u, --username`: Username for authenticated bind
- `-p, --password`: Password for authenticated bind
- `-d, --domain`: Domain name (required for domain searches)
- `--naming-contexts`: Discover available naming contexts
- `--enumerate`: Enumerate objects in a specific naming context
- `--get-object`: Get detailed attributes for a specific object DN (works with users, groups, computers, etc.)
- `--filter`: Custom LDAP filter (default: "(objectClass=*)")
- `-l, --list`: List users, groups, or all objects
- `--search`: Search for a specific username

## Examples

**Discover naming contexts** (equivalent to `ldapsearch -x -h $IP -b "" -s base namingcontexts`):
```bash
python3 myldap.py -s $IP --naming-contexts
```

**Enumerate naming context** (equivalent to `ldapsearch -x -h $IP -s sub -b "DC=example,DC=com"`):
```bash
python3 myldap.py -s $IP --enumerate "DC=example,DC=com"
```

**Get detailed object info** (equivalent to `ldapsearch -x -h $IP -b "CN=User,OU=Users,DC=domain,DC=com" "*"`):
```bash
python3 myldap.py -s $IP --get-object "CN=User,OU=Users,DC=domain,DC=com"
```

**Find object DN first, then get details**:
```bash
# Step 1: Find the object
python3 myldap.py -s 10.10.10.182 -d domain.local --enumerate "DC=domain,DC=local" --filter "(cn=John Doe)"

# Step 2: Use the returned DN
python3 myldap.py -s 10.10.10.182 --get-object "CN=John Doe,OU=Users,OU=UK,DC=domain,DC=local"
```

**Enumerate groups**:
```bash
python3 myldap.py -s $IP --enumerate "DC=domain,DC=local" --filter "(objectClass=group)"
```

**Get details of a specific group**:
```bash
python3 myldap.py -s $IP --get-object "CN=Domain Admins,CN=Users,DC=domain,DC=local"
```

**Enumerate computers**:
```bash
python3 myldap.py -s $IP --enumerate "DC=domain,DC=local" --filter "(objectClass=computer)"
```

**Get details of a specific computer**:
```bash
python3 myldap.py -s $IP --get-object "CN=WORKSTATION01,CN=Computers,DC=domain,DC=local"
```

## Binary Data Handling

The tool automatically formats binary LDAP attributes for better readability:

- **objectGUID**: Shows as Base64 with UUID format
- **objectSid**: Shows as Base64 (matching ldapsearch output)
- **Binary certificates**: Shows summary with data size
- **Password fields**: Automatically redacted for security
- **Other binary data**: Shows as Base64, with text interpretation when possible

## Requirements

- Python 3
- ldap3 library (`pip install ldap3`)

## Common Use Cases

1. **Initial reconnaissance**: Use `--naming-contexts` to discover available contexts
2. **Domain enumeration**: Use `--enumerate` with the domain DN to list all objects
3. **Object investigation**: First find objects with `--enumerate` + filter, then get details with `--get-object`
4. **Targeted searches**: Use custom `--filter` options for specific object types or attributes
5. **Group analysis**: Enumerate groups and then get member details using `--get-object`
6. **Computer enumeration**: Find and analyze computer accounts in the domain
7. **Permission auditing**: Use filters to find objects with specific attributes
8. **User account analysis**: Get comprehensive user attributes including group memberships

## Troubleshooting

- **"Object not found"**: Make sure you're using the complete DN path including all OUs
- **"Access denied"**: Try with authenticated bind using `-u`, `-p`, and `-d` options  
- **"Binary data garbled"**: The tool automatically handles this - you'll see Base64 encoded values
- **Connection issues**: The tool tries LDAPS first, then LDAP - check if ports 636 or 389 are open
- **Empty results**: Try with different filters or check if anonymous bind is allowed

