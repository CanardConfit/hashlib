# Ansible Collection - canardconfit.hashlib

This is an Ansible Collection that provides tools from [hashlib library](https://docs.python.org/3/library/hashlib.html).

## Getting Started

To get started, you can install this collection from Ansible Galaxy:

```bash
ansible-galaxy collection install canardconfit.hashlib
```

## Usage Example

Here is a basic usage example that demonstrates how to use the PBKDF2-HMAC hashing module:

```yaml
- name: Hash password with PBKDF2-HMAC
  hosts: localhost
  tasks:
    - name: Hash a password using the canardconfit.hashlib collection
      canardconfit.hashlib.pbkdf2_hmac_module:
        password: "my_secret_password"
        iterations: 20000
        output_format: "base64"
      register: hashed_password

    - name: Display hashed password
      debug:
        msg: "Hashed Password: {{ hashed_password.hash }}"
```

## Contributing

We welcome contributions to improve this collection! Please submit a pull request or open an issue if you have ideas for new features or find bugs.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE) for more details.

