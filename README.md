# Just Exit My Validators

This tool allows you to recover your node address using your mnemonic, derive all associated validator private keys, and generate a signed exit message - especially if you no longer have direct access to your smartnode.

> **Warning:** Because the tool accesses your mnemonic (which controls all your validator keys), **only your withdrawal address remains safe**. Use this tool only when you intend to exit all validators.

---

## FAQ

### 1. What does this tool do?
It recovers your node address using your mnemonic phrase and derives all the associated validator private keys. This functionality enables you to stop or disable a validator even if you don't have direct access to your smartnode.

### 2. When should I use this tool?
This tool is designed for situations where you **want to exit all validators** and do not have access to your synced smartnode. Because it compromises all validator private keys, it should only be used if you intend to exit every validator.

### 3. Why do I only need a mnemonic, without node access?
The smartnode is built on a Hierarchical Deterministic (HD) wallet architecture. All private keys are derived from a single mnemonic phrase—your mnemonic acts as a master key. This means you can recover every validator's private key without needing direct access to the node. For more details on HD wallets, check out [this article](https://medium.com/@blainemalone01/hd-wallets-why-hardened-derivation-matters-89efcdc71671).

### 4. Is it secure?
The tool requires access to your mnemonic, which gives it full access to your node wallet and all associated validator keys. **Only your withdrawal address remains safe.**  
To help mitigate risks, the tool is [open source](https://github.com/0xtrooper/JustExitMyValidators) and designed to run locally, ensuring that your sensitive data remains on your own device.

### 5. How do I set a withdrawal address?
For enhanced security, **it is highly recommended that you set a primary withdrawal address if you haven't already done so.** Learn how to set one by following [this guide](https://docs.rocketpool.net/guides/node/prepare-node#setting-your-primary-withdrawal-address).

### 6. How does it integrate with Beaconcha.in?
The tool generates a signed exit message that you can broadcast using Beaconcha.in to start your validator's exit process.

---

## Exit Process Guide

Follow these steps to exit your validators:

1. **Review the FAQ**  
   Before you begin, please carefully read the [FAQ](#faq) for important details.

2. **Set a Separate Withdrawal Address**  
   Ensure that your withdrawal address is different from your node address.

3. **Enter Your Mnemonic**  
   Input your mnemonic phrase as shown in the example below.  
   ![Mnemonic Input Example](/images/enterMnemonic.png)

4. **Select the Correct Node Address**  
   Choose the correct node address from the three most common derivation paths displayed by the interface.  
   ![Node Address Selection](/images/confirmNodeAddress.png)

5. **Extended Settings**  
   If your node address isn't displayed, click the "Extended Settings" option to reveal additional settings. In this section you can manually specify the derivation path.  
   - **Derivation Path Requirements:**  
     - Must start with `m/44/60` (or `m/44'/60'`).  
     - Examples:  
       - `m/44/60/123/0/0`  
       - `m/44'/60'/132'/0'/0`  
     - You can also include a placeholder for the index using a path like:  
       - `m/44'/60'/123'/0'/%d` (where `%d` is replaced by the desired index)  
   - A custom index (default is `0`) may also be specified if needed.

6. **Load the Minipool List**  
   The minipool list will load shortly. Without a Beaconcha.in API key, this may take a few seconds.  
   ![Minipool List Loading](/images/minipoolList.png)

7. **Select Validators to Exit**  
   Choose the minipools/validators you wish to exit, then click the **Sign Exit** button to generate the exit message. A confirmation prompt will appear.  
   ![Sign Exit Confirmation](/images/confirmExit.png)

8. **Copy and Broadcast the Exit Message**  
   Click the button to copy your exit message, then follow the provided link to Beaconcha.in to broadcast it.  
   ![Broadcast Exit Message](/images/submitExit.png)

9. **Submit the Message**  
   Paste the exit message and submit it. The broadcast process may take a few moments; once complete, the final status will display as **COMPLETED**.  
   ![Exit Completed](/images/broadcastCompleted.png)

---

## Requirements

1. **Go (version 1.22+ recommended)**
    - You can download and install Go from the official [Go Downloads page](https://go.dev/dl/).  
    - Refer to the official [Getting Started](https://go.dev/doc/install) guide for further instructions.  
    - Earlier versions (e.g., 1.20, 1.21) may still work, but are **not** tested.

2. **Optional: RPC or Beaconcha.in API Key**  
    For faster loading times and improved reliability, you can provide an RPC endpoint or a Beaconcha.in API key. They can be entered at the settings at the top right on the page.
    - **RPC Endpoint:**  
    - **Beaconcha.in API Key:**  
        - You can obtain an API key by signing up on the [Beaconcha.in website](https://beaconcha.in). 


---

## Installation

You will need to **install Go** (1.22+ recommended) and build from source:

1. **Clone this repository**:

    ```bash
    git clone https://github.com//0xtrooper/JustExitMyValidators.git && cd JustExitMyValidators    
    ```

2. **Build the binary**:

    ```bash
    go build justExitMyValidators
    ```

    **Note**: This will download the necessary packages if they are not already cached.

3. **Run the CLI tool**:

    ```bash
    ./justExitMyValidators
    ``` 

---

## Advanced Options

This tool supports several advanced command line flags to customize its behavior. You can use these options to enable debug mode, specify custom Ethereum RPC endpoints, and change the server's port.

- **--debug**  
  Enables debug mode.  
  **Usage:** `--debug`
  **Example:** `./justExitMyValidators --debug`  
  **Default:** `false`

- **--rpc-mainnet**  
  Specifies the Ethereum RPC URL for the mainnet - overwrites the default.
  **Note:** It's generally better to just use the UI for network configuration.  
  **Usage:** `--rpc-mainnet <URL>`  
  **Example:** `./justExitMyValidators --rpc-mainnet https://mainnet.infura.io/v3/YOUR_API_KEY`

- **--rpc-holesky**  
  Specifies the Ethereum RPC URL for the Holesky network - overwrites the default.  
  **Note:** It's generally better to just use the UI for network configuration.  
  **Usage:** `--rpc-holesky <URL>`  
  **Example:** `./justExitMyValidators --rpc-holesky https://holesky.infura.io/v3/YOUR_API_KEY`

- **--port**  
  Sets the port for the server to run on.  
  **Usage:** `--port <port>`  
  **Example:** `./justExitMyValidators --port 9090`  
  **Default:** `8080`