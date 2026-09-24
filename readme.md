# CrossPilot [![GitHub stars](https://img.shields.io/github/stars/Giancarlo1974/winboat-bridge.svg?style=social)](https://github.com/Giancarlo1974/winboat-bridge/stargazers)


![Windows server running with .env configuration](docs/quickstart-images/header.png)

**Remote execution, file transfer, and synchronization between Linux and Windows.**

CrossPilot is a lightweight remote agent designed to control **Windows and Linux** machines from another system, through a dedicated binary protocol.

It lets you execute commands, transfer files, synchronize directories, and manage remote filesystems without requiring Remote Desktop, SSH, or SMB shares.

> **One agent. Any host. Full control.**

---

## ✨ What you can do with CrossPilot

CrossPilot provides a single remote channel for system operations:

* 🖥️ **Remote command execution**
* 📤 **File upload**
* 📥 **File download**
* 🔄 **Directory synchronization**
* ⚡ **Incremental transfers**
* 🔐 **SHA-256 file verification**
* 📁 **Recursive directory creation**
* 🗑️ **File and directory deletion**
* 📋 **Remote filesystem listing**
* 🚀 **Automatic agent deployment**
* 🧩 **Windows and Linux support**
* 📦 **Standalone agent**
* 🐳 **Usable with VMs, containers, and physical machines**

CrossPilot is designed to be used both manually from the CLI and as a component of automation systems.

---

# 🏗️ Architecture

CrossPilot uses a **controller / agent** architecture.

```text
              CrossPilot Controller
                       │
                       │ TCP
                       │
             ┌─────────┴─────────┐
             │                   │
       CrossPilot Agent    CrossPilot Agent
             │                   │
          Windows              Linux
```

The controller sends operations to the remote agent.

The agent executes the operation using the operating system's native primitives.

### Supported operations

```text
EXEC
PUT
GET
LIST
MKDIR
DELETE
SYNC
```

The goal is to keep the protocol operating-system independent.

---

# 🎯 Why CrossPilot?

CrossPilot was born to solve a simple problem:

> **How do you control a remote machine without depending on a specific remote access system?**

SSH is excellent for Linux.

WinRM is useful in the Windows ecosystem.

SMB is great for sharing filesystems.

RDP is designed to interact with a desktop.

CrossPilot takes a different approach:

**a single protocol for remote system operations.**

This makes it possible to build on top of the same agent:

* CLI tools
* provisioning systems
* DevOps automation
* CI/CD
* VM management
* remote machine management
* orchestrators
* development tools
* desktop applications

---

# ⚡ Remote Execution

CrossPilot can run programs and commands on the remote machine.

On Windows it can run, for example:

```text
cmd.exe
PowerShell
.exe
.bat
.cmd
```

On Linux the backend can use:

```text
/bin/sh
bash
```

Conceptual example:

```bash
crosspilot exec server01 -- "hostname"
```

or:

```bash
crosspilot exec server01 -- "powershell Get-Process"
```

The agent starts the process on the remote system and forwards the output to the controller.

---

# 📁 File Transfer

CrossPilot supports bidirectional transfer:

```text
Controller ──────── PUT ────────> Agent
Controller <──────── GET ──────── Agent
```

Example:

```bash
crosspilot put ./app.exe server01:/opt/app/app.exe
```

and:

```bash
crosspilot get server01:/var/log/app.log ./app.log
```

The transfer uses a dedicated binary protocol instead of going through shell command encoding.

---

# ⚡ Incremental Transfers

For large files, CrossPilot can avoid re-transferring data that is already present on the remote system.

The file is split into segments and block signatures are generated.

```text
Local file
     │
     ├── block 1
     ├── block 2
     ├── block 3
     ├── block 4
     └── ...
             │
             ▼
       Remote signatures
             │
             ▼
       Delta generation
             │
             ▼
    Transfer of only the
       necessary data
```

This approach is particularly useful for:

* disk images
* large databases
* build artifacts
* application directories
* VMs
* files that change frequently

---

# 🔄 Directory Sync

CrossPilot can synchronize a local directory with a remote directory.

```bash
crosspilot sync ./build server01:/opt/myapp
```

During synchronization, the following are compared:

* path
* element type
* size
* possibly checksum

Elements can be classified as:

```text
NEW
CHANGED
MISSING
IDENTICAL
CONFLICT
```

Example:

```text
./build/
├── app.exe
├── config.json
└── assets/
    ├── logo.png
    └── index.html
```

can be synchronized to:

```text
C:\Apps\MyApp\
```

or:

```text
/opt/myapp/
```

---

# 🧹 Delete

Synchronization can optionally remove elements from the remote system that no longer exist in the source.

```bash
crosspilot sync ./build server01:/opt/myapp --delete
```

For destructive operations, the following mode is also available:

```bash
crosspilot sync ./build server01:/opt/myapp --dry-run
```

which shows the changes without applying them.

---

# 🔐 Data Integrity

CrossPilot uses SHA-256 to verify transfer integrity.

It is possible to verify:

* individual segments
* complete files
* received content

The transfer also uses temporary files:

```text
file.exe.part
```

The file is made available under its final name only after the transfer completes and is verified.

This prevents a partially transferred file from being left at the destination path.

---

# 📡 Protocol

CrossPilot uses a proprietary binary TCP protocol.

Each message is encapsulated in a frame:

```text
┌──────────┬─────────┬────────┬─────────────┬─────────┐
│ Magic    │ Version │ Type   │ Payload Len │ Payload │
│ 4 bytes  │ 1 byte  │ 1 byte │ 4 bytes     │ N bytes │
└──────────┴─────────┴────────┴─────────────┴─────────┘
```

Magic:

```text
DFB1
```

The protocol supports messages for:

```text
PUT
GET
SIGNATURE
DELTA
ACK
ERROR
META
LIST
MKDIR
DELETE
```

The structure is designed to allow new operations to be added without changing the base framing.

---

# 🖥️ Windows and Linux

CrossPilot is designed to separate:

```text
             Protocol
                  │
        ┌─────────┴─────────┐
        │                   │
 Windows backend       Linux backend
        │                   │
        ▼                   ▼
   Win32 / cmd          POSIX / shell
   Task Scheduler       systemd
   Job Objects          process groups
```

The protocol remains common while operating-system-specific operations are implemented by the respective backend.

This allows the same operating model to be used regardless of the remote system.

---

# 🚀 Agent Deployment

The controller can also handle agent bootstrap.

On Windows, deployment can use WinRM to:

1. check for the agent's presence
2. check the version
3. transfer the executable if necessary
4. configure the environment
5. start the agent

Once the agent is running, normal operations use the CrossPilot protocol.

In this way, WinRM can be used as the **initial control plane**, while CrossPilot becomes the **operational data plane**.

```text
          Bootstrap
             │
           WinRM
             │
             ▼
       Install Agent
             │
             ▼
       CrossPilot TCP
             │
      ┌──────┼──────┐
      ▼      ▼      ▼
     EXEC   FILE   SYNC
```

---

# 📦 Standalone Agent

The agent is designed to be distributed as a single executable.

This makes it possible to use it in:

* workstations
* servers
* VMs
* cloud machines
* physical machines
* test environments
* CI/CD
* containers

There is no need to install a complex runtime framework on the remote system.

---

# 🔧 Usage Examples

## Deploying an application

```bash
crosspilot sync ./dist server01:/opt/myapp --delete
```

then:

```bash
crosspilot exec server01 -- "/opt/myapp/start.sh"
```

---

## Managing a Windows server

```bash
crosspilot exec win01 -- "powershell Get-Service"
```

Upload:

```bash
crosspilot put ./app.exe win01:"C:\Apps\app.exe"
```

---

## Collecting logs

```bash
crosspilot get server01:/var/log/app.log ./logs/app.log
```

---

## Updating a VM

```bash
crosspilot sync ./release server01:/opt/release
```

Files that are already identical can be skipped, and modified files can use incremental transfer.

---

# 🧩 Possible Use Cases

CrossPilot can be used as a building block for:

### DevOps

* deployment
* provisioning
* updates
* log collection
* artifact management

### CI/CD

```text
Build
  │
  ▼
CrossPilot
  │
  ├── Upload
  ├── Sync
  ├── Execute
  └── Verify
```

### Virtualization

It can be used to manage Windows and Linux VMs without necessarily requiring a guest-specific protocol.

### Remote automation

An orchestrator can use CrossPilot as a backend to execute operations on nodes.

---

# 🧠 Philosophy

CrossPilot does not want to be yet another remote desktop.

It does not want to replace:

* RDP
* SSH
* SMB
* WinRM

Its goal is to provide a simpler, more uniform layer for **automation and remote operating system control**.

```text
             CrossPilot
                  │
       ┌──────────┼──────────┐
       │          │          │
     EXEC       FILE       SYNC
       │          │          │
       └──────────┼──────────┘
                  │
             Remote Host
```

A controller talks to an agent.

The agent translates operations into the language of the operating system.

---

# ⭐ Support the project (aka "The Star Section")

Building tools like this is fun, but seeing stars is better! 

If this tool saved you time or just made your life easier, please **drop a star** on this repository. It costs you $0.00, but it gives me the fuel (and the dopamine) to keep building and sharing more cool stuff for free. 

Go on, click that star. You know you want to! 😉

---

# 🤝 Contributing

Pull requests, issues, and contributions are welcome.

Particularly interesting areas are:

* Linux backend
* Windows backend
* protocol security
* transfer performance
* synchronization
* CLI
* API
* cross-platform testing
* documentation

---

## CrossPilot

**One agent. Any host. Full control.**
