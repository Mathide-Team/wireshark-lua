-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/ZhangTao1596/neo-wireshark-plugin (neo.lua),
-- commit f24c5133d3ed5b94183c76c6cd853ae596acb2ac du 06/12/2018.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
--V1.1.0 2018-11-1
do
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    M_MAINNET = 0x00746e41
    M_TESTNET = 0x74746e41
    M_PRIVNET = 0x00099e81

    C_VERSION       = "version"
    C_VERSION_ACK   = "verack"
    C_GET_ADDR      = "getaddr"
    C_ADDR          = "addr"
    C_GET_HEADERS   = "getheaders"
    C_HEADERS       = "headers"
    C_GET_BLOCKS    = "getblocks"
    C_INV           = "inv"
    C_GET_DATA      = "getdata"
    C_TX            = "tx"
    C_BLOCK         = "block"
    C_CONSENSUS     = "consensus"
    C_MEMPOOL       = "mempool"
    C_FILTER_CLEAR   = "filterclear"
    C_FILTER_LOAD    = "filterload"
    C_FILTER_ADD     = "filteradd"

    TX_MINER        = 0x00
    TX_ISSUE        = 0x01
    TX_CLAIM        = 0x02
    TX_CONTRACT     = 0x80
    TX_INVOCATION   = 0xd1

    ATTR_CONTRACTHASH   = 0x00
    ATTR_ECDH02         = 0x02
    ATTR_ECDH03         = 0x03
    ATTR_SCRIPT         = 0x20
    ATTR_VOTE           = 0x30
    ATTR_CERTURL        = 0x80
    ATTR_DESCRIPURL     = 0x81
    ATTR_DESCRIP        = 0x90
    ATTR_HASH1          = 0xa1
    ATTR_HASH15         = 0xaf
    ATTR_REMARK0        = 0xf0
    ATTR_REMARK15       = 0xff

    DATA_TX         = 0x01
    DATA_BLOCK      = 0x02
    DATA_CONCENSUS  = 0xe0
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    NET_TYPE = {
        [M_MAINNET] = "MainNet",
        [M_TESTNET] = "TestNet",
        [M_PRIVNET] = "PrivNet"
    }
    CMD_TYPE = {
        [C_VERSION]       = "VERSION",
        [C_VERSION_ACK]   = "VERACK",
        [C_GET_ADDR]      = "GETADR",
        [C_ADDR]          = "ADDR",
        [C_GET_HEADERS]   = "GETHEADERS",
        [C_HEADERS]       = "HEADERS",
        [C_GET_BLOCKS]    = "GETBLOCKS",
        [C_INV]           = "INV",
        [C_GET_DATA]      = "GETDATA",
        [C_TX]            = "TX",
        [C_BLOCK]         = "BLOCK",
        [C_CONSENSUS]     = "CONSENSUS",
        [C_MEMPOOL]       = "MEMPOOL",
        [C_FILTER_CLEAR]   = "FILTERCLEAR",
        [C_FILTER_LOAD]    = "FILTERLOAD",
        [C_FILTER_ADD]     = "FILTERADD"
    }
    DATA_TYPE = {
        [DATA_TX]           = "Txs",
        [DATA_BLOCK]        = "Blocks",
        [DATA_CONCENSUS]    = "Concensus"
    }
    TX_TYPE = {
        [TX_MINER]      = "MinerTx",
        [TX_ISSUE]      = "IssueTx",
        [TX_CLAIM]      = "ClaimTx",
        [TX_CONTRACT]   = "ContractTx",
        [TX_INVOCATION] = "InvocationTx",
    }
    ATTR_USAGE_TYPE = {
        [ATTR_CONTRACTHASH]   = "ContractHash",
        [ATTR_ECDH02]         = "ECHH02",
        [ATTR_ECDH03]         = "ECHH03",
        [ATTR_SCRIPT]         = "Script",
        [ATTR_VOTE]           = "Vote",
        [ATTR_CERTURL]        = "CerUrl",
        [ATTR_DESCRIPURL]     = "DescriptionUrl",
        [ATTR_DESCRIP]        = "Description",
        [ATTR_HASH1]          = "Hash1",
        [ATTR_HASH15]         = "Hash15",
        [ATTR_REMARK0]        = "Remark0",
        [ATTR_REMARK15]       = "Remark15",
    }
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local function dprint(...)
        info(table.concat({"Lua: ", ...}, " "))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local function get_attr_type_str(type)
        if ATTR_HASH1 <= type and type <= ATTR_HASH15 then
            return "Hash"..tostring(type)
        elseif ATTR_REMARK0 <= type and type <= ATTR_REMARK15 then
            return "Remark"..tostring(type)
        end
        return ATTR_USAGE_TYPE[type]
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_hashes = Proto("Hashes", "hashes")
    neop2p_hashes.fields.count = ProtoField.uint8("hashes.count", "COUNT", base.DEC)
    neop2p_hashes.fields.hash = ProtoField.string("hashes.hash", "HASH", base.ASCII)

    local function neop2p_hashes_dissector(buffer,  pinfo, tree, offset)
        local count = buffer(offset, 1):le_uint()
        local index = 0

        local hashes_tree = tree:add(neop2p_hashes, buffer(offset, count * 32 + 1), "Hashes")
        hashes_tree:add(neop2p_hashes.fields.count, buffer(offset, 1), count)
        while (index < count) do
            hashes_tree:add(neop2p_hashes.fields.hash, buffer(offset + 1 + index * 32, 32), tostring(buffer(offset + 1 + index * 32, 32)))
            index = index + 1
        end
        return count * 32 + 1
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_script = Proto("script", "script")

    neop2p_script.fields.scriptlen = ProtoField.uint8("script.scriptlen", "LEN", base.DEC)
    neop2p_script.fields.script = ProtoField.string("script.script", "DATA", base.ASCII)

    local function get_script_length(buffer, offset)
        local slen = buffer(offset, 1):le_uint()
        return slen + 1
    end
    local function neop2p_script_dissector(buffer, pinfo, tree, offset, name)
        local scriptlen = buffer(offset, 1):le_uint()
        local script_tree = tree:add(neop2p_script, buffer(offset, scriptlen + 1), name)

        script_tree:add(neop2p_script.fields.scriptlen, buffer(offset, 1), scriptlen)
        if scriptlen == 0 then
            return 1
        end
        script_tree:add(neop2p_script.fields.script, buffer(offset + 1, scriptlen), tostring(buffer(offset + 1, scriptlen)))
        return scriptlen + 1
    end

    local neop2p_scripts = Proto("scripts", "scripts")

    neop2p_scripts.fields.count = ProtoField.uint8("scripts.count", "COUNT", base.DEC)

    local function get_scripts_length(buffer, offset)
        local len = buffer:len()
        local index = 0
        local loffset = 0
        local count = buffer(offset, 1):le_uint()
        loffset = loffset + 1
        while (index < count) do
            local result = get_script_length(buffer(offset + loffset, len - offset - loffset), offset + loffset)
            loffset = loffset + result
        end
        return loffset
    end
    local function neop2p_scripts_dissector(buffer, pinfo, tree, offset)
        local index = 0
        local local_offset = 0
        local count = buffer(offset, 1):le_uint()
        local scripts_tree = tree:add(neop2p_scripts, buffer(offset, get_scripts_length(buffer, offset)), "SCRIPTS")
        scripts_tree:add(neop2p_scripts.fields.count, buffer(offset, 1), count)
        local_offset = local_offset + 1
        while (index < count) do
            local result = neop2p_script_dissector(buffer, pinfo, scripts_tree, offset + 1 + index * count, "script")
            local_offset = local_offset + result
            index = index + 1
        end
        return local_offset
    end

    local neop2p_witness = Proto("NeoWitness", "Neo P2P Witness")

    local function get_witness_length(buffer, offset)
        local len1 = buffer(offset, 1):le_uint()
        local len2 = buffer(offset + 1 + len1, 1):le_uint()
        return len1 + len2 + 2
    end
    local function neop2p_witness_dissector(buffer, pinfo, tree, offset)
        local loffset = 0
        local witness_tree = tree:add(neop2p_witness, buffer(offset, get_witness_length(buffer, offset)), "WITNESS")
        result = neop2p_script_dissector(buffer, pinfo, witness_tree, offset, "INVOCATIONSCRIPT")
        loffset = loffset + result
        result = neop2p_script_dissector(buffer, pinfo, witness_tree, offset + loffset, "VERIFICATIONSCRIPT")
        loffset = loffset + result
        return loffset
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_coin = Proto("Coin", "coin reference")

    neop2p_coin.fields.prehash = ProtoField.string("coin.prehash", "PREHASH", base.ASCII)
    neop2p_coin.fields.preindex = ProtoField.uint16("coin.preindex", "PREINDEX", base.DEC)

    local function neop2p_coin_dissector(buffer, pinfo, tree, offset)
        local coin_tree = tree:add(neop2p_coin, buffer(offset, 34), "COIN")
        coin_tree:add(neop2p_coin.fields.prehash, buffer(offset, 32), tostring(buffer(offset, 32)))
        coin_tree:add(neop2p_coin.fields.preindex, buffer(offset + 32, 2), buffer(offset, 2):le_uint())
        return 34
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_coins = Proto("Coins", "coin reference array")
    
    neop2p_coins.fields.count = ProtoField.uint8("coins.count", "COUNT", base.DEC)

    local function neop2p_coins_dissector(buffer, pinfo, tree, offset, name)
        local index = 0
        local count = buffer(offset, 1):le_uint()
        local coins_tree = tree:add(neop2p_coins, buffer(offset, 1 + count * 34), name)
        coins_tree:add(neop2p_coins.fields.count, buffer(offset, 1), count)
        while (index < count) do
            local result = neop2p_coin_dissector(buffer, pinfo, coins_tree, offset + 1 + index * count)
            index = index + 1
        end
        return count * 34 + 1
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_output = Proto("Output", "transaction output")

    neop2p_output.fields.assetid = ProtoField.string("output.assetid", "ASSETID", base.ASCII)
    neop2p_output.fields.value = ProtoField.uint64("output.value", "VALUE", base.DEC)
    neop2p_output.fields.scripthash = ProtoField.uint16("output.scripthash", "SCRIPTHASH", base.DEC)

    local function neop2p_output_dissector(buffer, pinfo, tree, offset)
        local output_tree = tree:add(neop2p_coin, buffer(offset, 60), "Output")
        output_tree:add(neop2p_output.fields.assetid, buffer(offset, 32), tostring(buffer(offset, 32)))
        output_tree:add(neop2p_output.fields.value, buffer(offset + 32, 8), buffer(offset + 32 + 8, 8):le_uint64())
        output_tree:add(neop2p_output.fields.scripthash, buffer(offset + 40, 20), tostring(buffer(offset, 20)))
        return 60
    end

    local neop2p_outputs = Proto("Outpus", "transaction outpus")

    neop2p_outputs.fields.count = ProtoField.uint8("outputs.count", "COUNT", base.DEC)

    local function neop2p_outputs_dissector(buffer, pinfo, tree, offset)
        local index = 0
        local local_offset = 0
        local count = buffer(offset, 1):le_uint()
        local outputs_tree = tree:add(neop2p_outputs, buffer(offset + local_offset, 1 + count * 60), "Outputs")
        outputs_tree:add(neop2p_outputs.fields.count, buffer(offset + local_offset, 1), count)
        local_offset = local_offset + 1
        while (index < count) do
            local result = neop2p_coin_dissector(buffer, pinfo, coins_tree, offset + local_offset)
            local_offset = local_offset + result
            index = index + 1
        end
        return local_offset
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_attr = Proto("Attribute", "transaction attribute")

    neop2p_attr.fields.usage = ProtoField.uint8("attr.usage", "USAGE", base.DEC)
    neop2p_attr.fields.length = ProtoField.uint8("attr.length", "LENGTH", base.DEC)
    neop2p_attr.fields.data = ProtoField.string("attr.data", "DATA", base.ASCII)

    local function get_attr_length(buffer, offset)
        local usage = buffer(offset, 1):le_uint()
        if usage == ATTR_CONTRACTHASH or usage == ATTR_VOTE or usage == ATTR_ECDH02 
        or usage == ATTR_ECDH03 or (ATTR_HASH1 <= usage and usage <= ATTR_HASH15) then
            local length = 32
            return length + 1
        end
        local length = buffer(offset + 1, 1):le_uint()
        return length + 2
    end
    local function neop2p_attr_dissector(buffer, pinfo, tree, offset)
        local usage = buffer(offset, 1):le_uint()
        if usage == ATTR_CONTRACTHASH or usage == ATTR_VOTE or usage == ATTR_ECDH02 
        or usage == ATTR_ECDH03 or (ATTR_HASH1 <= usage and usage <= ATTR_HASH15) then
            local length = 32
            local attr_tree = tree:add(neop2p_attr, buffer(offset, 1 + length), "Attribute")
            attr_tree:add(neop2p_attr.fields.usage, buffer(offset, 1), get_attr_type_str(usage))
            attr_tree:add(neop2p_attr.fields.data, buffer(offset + 1, length), tostring(buffer(offset + 1, length)))
            return length + 1
        end
        local length = buffer(offset + 1, 1):le_uint()
        local attr_tree = tree:add(neop2p_attr, buffer(offset, 2 + length), "Attribute")
        attr_tree:add(neop2p_attr.fields.usage, buffer(offset, 1), usage)
        attr_tree:add(neop2p_attr.fields.length, buffer(offset + 1, 1), length)
        attr_tree:add(neop2p_attr.fields.data, buffer(offset + 2, length), tostring(buffer(offset + 1, length)))
        return length + 2
    end

    local neop2p_attrs = Proto("Attributes", "transaction attributes")

    neop2p_attrs.fields.count = ProtoField.uint8("attrs.count", "COUNT", base.DEC)

    local function get_attrs_length(buffer, offset)
        local len = buffer:len()
        local index = 0
        local loffset = 0
        local count = buffer(offset, 1):le_uint()
        loffset = loffset + 1
        while (index < count) do
            local result = get_attr_length(buffer(offset + loffset, len - offset - loffset), offset + loffset)
            loffset = loffset + result
        end
        return loffset
    end
    local function neop2p_attrs_dissector(buffer, pinfo, tree, offset)
        local index = 0
        local local_offset = 0
        local count = buffer(offset, 1):le_uint()
        local attrs_tree = tree:add(neop2p_attrs, buffer(offset + local_offset, get_attrs_length(buffer, offset)), "ATTRIBUTES")
        attrs_tree:add(neop2p_outputs.fields.count, buffer(offset + local_offset, 1), count)
        local_offset = local_offset + 1
        while (index < count) do
            local result = neop2p_attr_dissector(buffer, pinfo, attrs_tree, offset + local_offset)
            local_offset = local_offset + result
            index = index + 1
        end
        return local_offset
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_tx = Proto("Transaction", "Neo P2P Transaction")

    neop2p_tx.fields.type = ProtoField.uint8("tx.type", "TYPE", base.DEC, TX_TYPE)
    neop2p_tx.fields.version = ProtoField.uint8("tx.version", "VERSION", base.DEC)
    ------exclusive
    --miner
    neop2p_tx.fields.nonce = ProtoField.uint32("tx.nonce", "NONCE", base.DEC)
    --claims
    --neop2p_tx.fields.claims = neop2p_coins
    --invocation
    --neop2p_tx.fields.script = neop2p_script
    neop2p_tx.fields.gas = ProtoField.uint64("tx.gas", "GAS", base.DEC)
    ------attributes
    --neop2p_tx.fields.attributes = neop2p_attr
    ------inputs
    --neop2p_tx.fields.inputs = neop2p_coins
    ------outpus
    --neop2p_tx.fields.outputs = neop2p_outputs
    neop2p_tx.fields.script = ProtoField.string("tx.script", "SCRIPT", base.ASCII)

    local function neop2p_tx_dissector(buffer, pinfo, tree)
        local offset = 0
        local tx_tree = tree:add(neop2p_tx, buffer, "Tx")
        local type = buffer(offset, 1):le_uint()
        tx_tree:add(neop2p_tx.fields.type, buffer(offset, 1), type)
        offset = offset + 1
        tx_tree:add(neop2p_tx.fields.version, buffer(offset, 1), buffer(offset, 1):le_uint())
        offset = offset + 1
        ----exclusive
        if type == TX_MINER then
            tx_tree:add(neop2p_tx.fields.nonce, buffer(offset, 4), buffer(offset, 4):le_uint())
            offset = offset + 4
        elseif type == TX_CLAIM then
            local result = neop2p_coins_dissector(buffer, pinfo, tx_tree, offset, "CLAIMS")
            offset = offset + result
        elseif type == TX_INVOCATION then
            local result = neop2p_script_dissector(buffer, pinfo, tx_tree, offset, "Script")
            offset = offset + result
            tx_tree:add(neop2p_tx.fields.gas, buffer(offset, 8), buffer(offset, 8):le_uint())
            offset = offset + 8
        end
        ----attributes
        local result = neop2p_attrs_dissector(buffer, pinfo, tx_tree, offset)
        offset = offset + result
        result = neop2p_coins_dissector(buffer, pinfo, tx_tree, offset, "INPUTS")
        offset = offset + result
        result = neop2p_outputs_dissector(buffer, pinfo, tx_tree, offset)
        offset = offset + result
        result = neop2p_scripts_dissector(buffer, pinfo, tx_tree, offset)
        offset = offset + result
        return offset
    end 
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_block = Proto("Block", "Neo P2P Block")
    
    neop2p_block.fields.version = ProtoField.uint32("block.version", "VERSION", base.DEC)
    neop2p_block.fields.preblock = ProtoField.string("block.preblock", "PREBLOCK", base.ASCII)
    neop2p_block.fields.merkleroot = ProtoField.string("block.merkleroot", "MERKLEROOT", base.ASCII)
    neop2p_block.fields.timestamp = ProtoField.uint32("block.timestamp", "TIMESTAMP", base.DEC)
    neop2p_block.fields.index = ProtoField.uint32("block.index", "INDEX", base.DEC)
    neop2p_block.fields.consecsusdata = ProtoField.uint64("block.consecsusdata", "CONSECSUSDATA", base.DEC)
    neop2p_block.fields.nextconsensus = ProtoField.string("block.nextconsensus", "NEXTCONSENSUS", base.ASCII)
    neop2p_block.fields._ = ProtoField.uint8("block._", "_", base.DEC)
    neop2p_block.fields.scriptcount = ProtoField.uint8("block.scriptcount", "scriptcount", base.DEC)
    neop2p_block.fields.script = ProtoField.string("block.script", "SCRIPT", base.ASCII)
    neop2p_block.fields.txs = ProtoField.string("block.txs", "TXS", base.ASCII)
    neop2p_block.fields.txscount = ProtoField.uint8("block.txscount", "TXSCOUNT", base.DEC)

    local function neop2p_block_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local offset = 0

        local block_tree = tree:add(neop2p_block, buffer, "Block")

        block_tree:add(neop2p_block.fields.version, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.preblock, buffer(offset, 32), tostring(buffer(offset, 32)))
        offset = offset + 32
        block_tree:add(neop2p_block.fields.merkleroot, buffer(offset, 32), tostring(buffer(offset, 32)))
        offset = offset + 32
        block_tree:add(neop2p_block.fields.timestamp, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.index, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.consecsusdata, buffer(offset, 8), buffer(offset, 8):le_uint64())
        offset = offset + 8
        block_tree:add(neop2p_block.fields.nextconsensus, buffer(offset, 20), tostring(buffer(offset, 20)))
        offset = offset + 20
        block_tree:add(neop2p_block.fields._, buffer(offset, 1), buffer(offset, 1):le_uint())
        offset = offset + 1
        local result = neop2p_script_dissector(buffer, pinfo, block_tree, offset, "invocation")
        offset = offset + result
        result = neop2p_script_dissector(buffer, pinfo, block_tree, offset, "verify")
        offset = offset + result
        local txs_count = buffer(offset, 1):le_uint()
        block_tree:add(neop2p_block.fields.txscount, buffer(offset, 1), txs_count)
        offset = offset + 1
        local index = 0
        while (index < txs_count) do
            local result = neop2p_tx_dissector(buffer(offset, len - offset), pinfo, block_tree)
            offset = offset + result
            index = index + 1
        end
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_getblocks = Proto("GetBlocks", "Neo P2P Get Blocks")

    neop2p_getblocks.fields.count = ProtoField.uint8("count", "COUNT", base.DEC)
    neop2p_getblocks.fields.hash = ProtoField.string("hashstop", "HASHSTOP", base.ASCII)

    local function neop2p_getblocks_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local offset = 0
        local getblocks_tree = tree:add(neop2p_getblocks, buffer(0, len), "GetBlocks")
        local result = neop2p_hashes_dissector(buffer, pinfo, getblocks_tree, 0)
        offset = offset + result
        getblocks_tree:add(neop2p_getblocks.fields.hash, buffer(offset, 32), tostring(buffer(offset, 32)))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_headers = Proto("Headers", "Neo P2P Headers")

    neop2p_headers.fields.count = ProtoField.uint8("count", "COUNT", base.DEC)

    local function neop2p_headers_dissector(buffer, pinfo, tree)
        local result = neop2p_hashes_dissector(buffer, pinfo, tree, 0)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_getheaders = Proto("GetHeaders", "Neo P2P Get Headers")

    neop2p_getheaders.fields.count = ProtoField.uint8("count", "COUNT", base.DEC)
    neop2p_getheaders.fields.hash = ProtoField.string("hashstop", "HASHSTOP", base.ASCII)

    local function neop2p_getheaders_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local offset = 0
        local getheaders_tree = tree:add(neop2p_getheaders, buffer(0, len), "GetHeaders")
        local result = neop2p_hashes_dissector(buffer, pinfo, getheaders_tree, 0)
        offset = offset + result
        getheaders_tree:add(neop2p_getheaders.fields.hash, buffer(offset, 32), tostring(buffer(offset, 32)))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_consensus = Proto("Consensus", "Neo P2P Consensus")

    neop2p_consensus.fields.version = ProtoField.uint32("consensus.version", "VERSION", base.DEC)
    neop2p_consensus.fields.prehash = ProtoField.string("consensus.prehash", "PREHASH", base.ASCII)
    neop2p_consensus.fields.blockindex = ProtoField.uint32("consensus.blockindex", "BLOCKINDEX", base.DEC)
    neop2p_consensus.fields.validatorindex = ProtoField.uint16("consensus.validatorindex", "VALIDATORINDEX", base.DEC)
    neop2p_consensus.fields.timestamp = ProtoField.uint32("consensus.timestamp", "TIMESTAMP", base.DEC)
    ----data
    --neop2p_consensus.fields.data = 
    neop2p_consensus.fields.witnesscount = ProtoField.uint8("consensus.witnesscount", "WITNESSCOUNT", base.DEC)
    --neop2p_consensus.fields.invocationscript = 
    --neop2p_consensus.fields.verificationscript = 

    local function neop2p_consensus_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        
        local con_tree = tree:add(neop2p_consensus, buffer(0, len), "Consensus")
        local offset = 0
        con_tree:add(neop2p_consensus.fields.version, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        con_tree:add(neop2p_consensus.fields.prehash, buffer(offset, 32), tostring(buffer(offset, 32)))
        offset = offset + 32
        con_tree:add(neop2p_consensus.fields.blockindex, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        con_tree:add(neop2p_consensus.fields.validatorindex, buffer(offset, 2), buffer(offset, 2):le_uint())
        offset = offset + 2
        con_tree:add(neop2p_consensus.fields.timestamp, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        local result = neop2p_script_dissector(buffer, pinfo, con_tree, offset, "DATA")
        offset = offset + result
        local witness_count = buffer(offset, 1):le_uint()
        con_tree:add(neop2p_consensus.fields.witnesscount, buffer(offset, 1), buffer(offset, 1):le_uint())
        offset = offset + 1
        local index = 0
        while (index < witness_count) do
            local result = neop2p_witness_dissector(buffer, pinfo, con_tree, offset)
            offset = offset + result
            index = index + 1
        end
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_ver = Proto("Version", "Neo P2P Version")

    neop2p_ver.fields.version = ProtoField.uint32("version.version", "VERSION", base.DEC)
    neop2p_ver.fields.services = ProtoField.uint64("version.services", "SERVICES", base.DEC)
    neop2p_ver.fields.timestamp = ProtoField.uint32("version.timestamp", "TIMESTAMP", base.DEC)
    neop2p_ver.fields.port = ProtoField.uint16("version.port", "PORT", base.DEC)
    neop2p_ver.fields.nonce = ProtoField.uint32("version.nonce", "NONCE", base.DEC)
    neop2p_ver.fields.useragent = ProtoField.string("version.useragent", "USERAGENT", base.ASCII)
    neop2p_ver.fields.height = ProtoField.uint32("version.height", "HEIGHT", base.DEC)
    neop2p_ver.fields.relay = ProtoField.bool("version.relay", "RELAY", base.NONE)

    local function neop2p_ver_dissector(buffer, pinfo, tree)
        local L = buffer:len()
        local useragent_len = L - 27
        
        local ver_tree = tree:add(neop2p_ver, buffer(0, L), "Version")
        local offset = 0
        ver_tree:add(neop2p_ver.fields.version, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.services, buffer(offset, 8), buffer(offset, 8):le_uint64())
        offset = offset + 8
        ver_tree:add(neop2p_ver.fields.timestamp, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.port, buffer(offset, 2), buffer(offset, 2):le_uint64():tonumber())
        offset = offset + 2
        ver_tree:add(neop2p_ver.fields.nonce, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.useragent, buffer(offset, useragent_len), buffer(offset, useragent_len):string())
        offset = offset + useragent_len
        ver_tree:add(neop2p_ver.fields.height, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.relay, buffer(offset, 1), buffer(offset, 1):le_uint())
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_getdata = Proto("GetData", "Neo P2P Get Data")

    neop2p_getdata.fields.type = ProtoField.uint8("inv.type", "TYPE", base.DEC, DATA_TYPE)
    neop2p_getdata.fields.count = ProtoField.uint8("inv.count", "COUNT", base.DEC)

    local function neop2p_getdata_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local data_type = buffer(0, 1):uint()
        local hash_count  = buffer(1, 1):uint()

        local getdata_tree = tree:add(neop2p_getdata, buffer(0, len), "GetData")
        getdata_tree:add(neop2p_getdata.fields.type, buffer(0, 1), buffer(0, 1):le_uint64():tonumber())
        local result = neop2p_hashes_dissector(buffer, pinfo, getdata_tree, 1)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_addr = Proto("GetAddr", "Neo P2P Get Address")

    neop2p_addr.fields.count = ProtoField.uint8("getaddr.count", "COUNT", base.DEC)

    local neop2p_oneaddr = Proto("Address", "address")

    neop2p_oneaddr.fields.timestamp = ProtoField.uint32("addr.timestamp", "TIMESTAMP", base.DEC)
    neop2p_oneaddr.fields.services = ProtoField.uint64("addr.services", "SERVICES", base.DEC)
    -- addr.fields.ipv6 = ProtoField.string("addr.ipv6", "IPV6", base.DEC)
    -- addr.fields.port = ProtoField.string("addr.port", "PORT", base.DEC)
    neop2p_oneaddr.fields.iport = ProtoField.string("addr.iport", "IPORT", base.ASCII)

    local function neop2p_addr_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local addr_count = buffer(0, 1):uint()
    
        local addr_tree = tree:add(neop2p_addr, buffer(0, len), "GetAddress")

        addr_tree:add(neop2p_addr.fields.count, buffer(0, 1), addr_count)

        local index = 0
        while (index < addr_count) do
            local addr = addr_tree:add(neop2p_oneaddr, buffer(1 + index * 30, 30), "Address")
            addr:add(neop2p_oneaddr.fields.timestamp, buffer(1 + index * 30, 4), buffer(1 + index * 30, 4):le_uint64():tonumber())
            addr:add(neop2p_oneaddr.fields.services, buffer(1 + index * 30, 8), buffer(1 + index * 30, 8):le_uint64())
            addr:add(neop2p_oneaddr.fields.iport, buffer(1 + index * 30, 18), tostring(buffer(1 + index * 30, 18)))
            index = index + 1
        end
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_inv = Proto("InvData", "Neo P2P Version Data")

    neop2p_inv.fields.type = ProtoField.uint8("inv.type", "TYPE", base.DEC, DATA_TYPE)
    neop2p_inv.fields.count = ProtoField.uint8("inv.count", "COUNT", base.DEC)

    local function neop2p_inv_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local inv_type = buffer(0, 1):uint()
        local hash_count  = buffer(1, 1):uint()

        local inv_tree = tree:add(neop2p_inv, buffer(0, len), "InvData")
        inv_tree:add(neop2p_inv.fields.type, buffer(0, 1), buffer(0, 1):le_uint64():tonumber())
        local result = neop2p_hashes_dissector(buffer, pinfo, inv_tree, 1)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neop2p = Proto("NEO", "Neo P2P Protocol")

        neop2p.fields.magic = ProtoField.uint32("neop2p.magic", "MAGIC", base.DEC, NET_TYPE)
        neop2p.fields.cmd = ProtoField.string("neop2p.cmd", "COMMAND", base.UNICODE)
        neop2p.fields.length = ProtoField.uint32("neop2p.length", "LENGTH", base.DEC)
        neop2p.fields.checksum = ProtoField.uint32("neop2p.checksum", "CHECKSUM", base.DEC)
        neop2p.fields.payload = ProtoField.string("neop2p.payload", "PAYLOAD", base.ASCII)

        local function neop2p_dissector(buffer, pinfo, tree)
            local L = buffer:len()
            local magic = buffer(0, 4):le_uint()
            local cmd = buffer(4, 12):stringz()
            local length = buffer(16, 4):le_uint()

            local p2p_tree = tree:add(neop2p, buffer(0, L), "Neo P2P Protocol, "..NET_TYPE[magic])
            pinfo.cols.protocol:set("NEO")
            pinfo.cols.info:set(" ".. NET_TYPE[magic]..":"..cmd)
    
            local offset = 0

            p2p_tree:add(neop2p.fields.magic, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            p2p_tree:add(neop2p.fields.cmd, buffer(offset, 12), buffer(offset, 12):string())
            offset = offset + 12
            p2p_tree:add(neop2p.fields.length, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            p2p_tree:add(neop2p.fields.checksum, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            if length == 0 then
                return true
            end
            local payload = buffer(offset, length)
            if cmd == C_INV then
                neop2p_inv_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_ADDR then
                neop2p_addr_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_GET_DATA then
                neop2p_getdata_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_VERSION then
                neop2p_ver_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_GET_HEADERS then
                neop2p_getheaders_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_BLOCK then
                neop2p_block_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_GET_BLOCKS then
                neop2p_getblocks_dissector(payload, pinfo, p2p_tree)
                return
            end
            if cmd == C_CONSENSUS then
                neop2p_consensus_dissector(payload, pinfo, p2p_tree)
                return
            end
            p2p_tree:add(neop2p.fields.payload, payload, tostring(payload))
            offset = offset + length
            return true
        end
        
        local function neop2p_detector(buffer, pinfo, tree, offset)
            local len = buffer:len() - offset
            if len < 4 then
                return 0 
            end
            local magic = buffer(offset, 4):le_uint()
            if NET_TYPE[magic] == nil then 
                return 0 
            end
            if len < 24 then
                return len - 24
            end
            local length = buffer(offset + 16, 4):le_uint() + 24
            local cmd = buffer(offset + 4, 12):stringz()
            if len < length then
                return len - length
            end
            neop2p_dissector(buffer(offset, length), pinfo, tree)
            return length
        end
     ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neo = Proto("NEOPROTOCOL", "Neo Protocol")
    
        function neo.dissector(buffer, pinfo, tree)
            local len = buffer:len()
            local offset = 0

            while offset < len do
     
                local result = neop2p_detector(buffer, pinfo, tree, offset)

                if 0 < result  then
                    offset = offset + result
                elseif 0 == result then
                    return 0
                else 
                    pinfo.desegment_offset = offset
                    result = -result
                    pinfo.desegment_len = result
                    return len
                end
            end
            return
        end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        neo:register_heuristic("tcp", neo.dissector)
    end