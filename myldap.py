#!/usr/bin/env python3

import argparse
import base64
import uuid
import ssl
from ldap3 import Server, Connection, ALL, SUBTREE, Tls

def create_ldap_connection(server_ip, username, password, domain):
    bind_user = f'{username}@{domain}'
    tls = Tls(validate=ssl.CERT_NONE)

    # Try LDAPS first
    try:
        print("[*] Trying LDAPS (port 636)...")
        server = Server(server_ip, use_ssl=True, get_info=ALL, tls=tls)
        conn = Connection(server, user=bind_user, password=password, auto_bind=True)
        print("[+] Connected over LDAPS")
        return conn
    except Exception as e:
        print(f"[!] LDAPS failed: {e}")
        print("[*] Falling back to LDAP (port 389)...")

    # Fallback to LDAP
    try:
        server = Server(server_ip, use_ssl=False, get_info=ALL)
        conn = Connection(server, user=bind_user, password=password, auto_bind=True)
        print("[+] Connected over LDAP")
        return conn
    except Exception as e:
        print(f"[-] LDAP connection failed: {e}")
        return None

def domain_to_basedn(domain):
    """Convert domain to base DN."""
    return ','.join([f'dc={part}' for part in domain.split('.')])

def format_binary_attribute(attr_name, attr_value):
    """Format binary attributes for human-readable display."""
    if isinstance(attr_value, bytes):
        # Handle specific binary attributes
        if attr_name.lower() == 'objectguid':
            try:
                # Convert GUID bytes to standard UUID format
                guid = uuid.UUID(bytes_le=attr_value)
                return f"{base64.b64encode(attr_value).decode('utf-8')} (UUID: {str(guid)})"
            except:
                return base64.b64encode(attr_value).decode('utf-8')
        
        elif attr_name.lower() == 'objectsid':
            return base64.b64encode(attr_value).decode('utf-8')
        
        elif attr_name.lower() in ['usercertificate', 'cacertificate', 'certificaterevocationlist']:
            return f"[Binary Certificate Data - {len(attr_value)} bytes]"
        
        elif attr_name.lower() in ['userpassword', 'unicodepwd', 'ntpwdhistory', 'lmpwdhistory']:
            return "[REDACTED - Password Field]"
        
        else:
            # For other binary data, show both base64 and try to decode as text if possible
            b64_data = base64.b64encode(attr_value).decode('utf-8')
            try:
                text_data = attr_value.decode('utf-8', errors='ignore')
                if text_data.isprintable():
                    return f"{b64_data} (Text: {text_data})"
            except:
                pass
            return b64_data
    
    return attr_value

def get_naming_contexts(server_ip, username=None, password=None, domain=None):
    """Discover naming contexts from LDAP server."""
    server = Server(server_ip, get_info=ALL)
    
    if username and password and domain:
        bind_user = f'{username}@{domain}'
        conn = create_ldap_connection(server_ip, username, password, domain)
        if not conn:
            print("[-] Could not establish LDAP or LDAPS connection")
            return
        print(f"[*] Authenticated bind as {bind_user}")
    else:
        conn = Connection(server, auto_bind=True)
        print("[*] Anonymous bind")
    
    print("[*] Discovering naming contexts...")
    conn.search('', '(objectClass=*)', search_scope='BASE', attributes=['namingContexts'])
    
    naming_contexts = []
    if conn.entries:
        for entry in conn.entries:
            if hasattr(entry, 'namingContexts'):
                naming_contexts = entry.namingContexts.values
                break
    
    if naming_contexts:
        print("[+] Found naming contexts:")
        for i, context in enumerate(naming_contexts, 1):
            print(f"    {i}. {context}")
    else:
        print("[-] No naming contexts found")
    
    conn.unbind()
    return naming_contexts

def enumerate_naming_context(server_ip, base_dn, username=None, password=None, domain=None, search_filter='(objectClass=*)'):
    """Enumerate objects within a specific naming context."""
    server = Server(server_ip, get_info=ALL)
    
    if username and password and domain:
        bind_user = f'{username}@{domain}'
        conn = create_ldap_connection(server_ip, username, password, domain)
        if not conn:
            print("[-] Could not establish LDAP or LDAPS connection")
            return
        print(f"[*] Authenticated bind as {bind_user}")
    else:
        conn = Connection(server, auto_bind=True)
        print("[*] Anonymous bind")
    
    print(f"[*] Enumerating naming context: {base_dn}")
    print(f"[*] Using filter: {search_filter}")
    
    try:
        conn.search(base_dn, search_filter, search_scope=SUBTREE, 
                   attributes=['cn', 'sAMAccountName', 'memberOf', 'objectClass', 'distinguishedName'])
        
        if conn.entries:
            print(f"[+] Found {len(conn.entries)} entries:")
            for entry in conn.entries:
                print(f"\n{entry.distinguishedName}")
                if hasattr(entry, 'objectClass'):
                    print(f"  Object Classes: {', '.join(entry.objectClass.values)}")
                if hasattr(entry, 'cn'):
                    print(f"  CN: {entry.cn}")
                if hasattr(entry, 'sAMAccountName'):
                    print(f"  sAMAccountName: {entry.sAMAccountName}")
        else:
            print("[-] No entries found")
    except Exception as e:
        print(f"[-] Error during search: {e}")
    
    conn.unbind()

def get_object_details(server_ip, object_dn, username=None, password=None, domain=None):
    """Get detailed attributes for a specific object DN (user, group, or any LDAP object)."""
    server = Server(server_ip, get_info=ALL)
    
    if username and password and domain:
        bind_user = f'{username}@{domain}'
        conn = create_ldap_connection(server_ip, username, password, domain)
        if not conn:
            print("[-] Could not establish LDAP or LDAPS connection")
            return
        print(f"[*] Authenticated bind as {bind_user}")
    else:
        conn = Connection(server, auto_bind=True)
        print("[*] Anonymous bind")
    
    print(f"[*] Getting details for object: {object_dn}")
    
    try:
        # Search for the specific object and get all attributes
        conn.search(object_dn, '(objectClass=*)', search_scope='BASE', attributes='*')
        
        if conn.entries:
            entry = conn.entries[0]
            print(f"\n[+] Object Details for: {entry.distinguishedName}")
            print("=" * 60)
            
            # Sort attributes for better readability
            attrs = sorted(entry.entry_attributes_as_dict.items())
            
            for attr_name, attr_values in attrs:
                if len(attr_values) == 1:
                    formatted_value = format_binary_attribute(attr_name, attr_values[0])
                    print(f"{attr_name}: {formatted_value}")
                else:
                    print(f"{attr_name}:")
                    for value in attr_values:
                        formatted_value = format_binary_attribute(attr_name, value)
                        print(f"  - {formatted_value}")
        else:
            print("[-] Object not found or no access to object")
    except Exception as e:
        print(f"[-] Error retrieving object details: {e}")
    
    conn.unbind()

def ldap_search(domain, username, password, server_ip, search_user=None, list_type=None):
    # Convert domain to base DN
    base_dn = domain_to_basedn(domain)
    
    # Define search filter
    if list_type == 'users':
        search_filter = '(&(objectClass=user)(!(objectClass=computer)))'
    elif list_type == 'groups':
        search_filter = '(objectClass=group)'
    elif list_type == 'all':
        search_filter = '(objectClass=*)'
    elif search_user:
        search_filter = f'(sAMAccountName={search_user})'
    else:
        print("[!] Must provide --search or --list option.")
        return

    # Connect to LDAP server
    server = Server(server_ip, get_info=ALL)

    if username and password:
        # Use UPN for bind
        bind_user = f'{username}@{domain}'
        conn = create_ldap_connection(server_ip, username, password, domain)
        if not conn:
            print("[-] Could not establish LDAP or LDAPS connection")
            return
        print(f"[*] Authenticated bind as {bind_user}")
    else:
        conn = Connection(server, auto_bind=True)
        print("[*] Anonymous bind")

    # Perform search
    conn.search(base_dn, search_filter, attributes=['cn', 'sAMAccountName', 'memberOf', 'objectClass'])
    
    # Output results
    for entry in conn.entries:
        print(entry)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auto LDAP search and enumeration tool with anonymous bind')
    parser.add_argument('-u', '--username', help='Username for authenticated bind')
    parser.add_argument('-p', '--password', help='Password for authenticated bind')
    parser.add_argument('-d', '--domain', help='Domain, e.g., administrator.htb (required for domain searches)')
    parser.add_argument('-s', '--server', required=True, help='LDAP server IP or hostname')
    parser.add_argument('--search', help='Specific username to search for')
    parser.add_argument('-l', '--list', choices=['users', 'groups', 'all'], help='List all users, groups, or everything')
    parser.add_argument('--naming-contexts', action='store_true', help='Discover naming contexts')
    parser.add_argument('--enumerate', help='Enumerate specific naming context (e.g., "DC=example,DC=com")')
    parser.add_argument('--get-object', help='Get detailed attributes for a specific object DN (user, group, etc.) (e.g., "CN=John Doe,DC=example,DC=com")')
    parser.add_argument('--filter', default='(objectClass=*)', help='LDAP filter for enumeration (default: "(objectClass=*)")')

    args = parser.parse_args()
    
    if args.naming_contexts:
        get_naming_contexts(args.server, args.username, args.password, args.domain)
    elif args.enumerate:
        enumerate_naming_context(args.server, args.enumerate, args.username, args.password, args.domain, args.filter)
    elif args.get_object:
        get_object_details(args.server, args.get_object, args.username, args.password, args.domain)
    elif args.domain:
        ldap_search(args.domain, args.username, args.password, args.server, args.search, args.list)
    else:
        print("[!] Must provide --domain for domain searches, --naming-contexts for discovery, --enumerate for enumeration, or --get-object for object details.")
        parser.print_help()
