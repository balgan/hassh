#                               HASSH                                #
#             SSH Key Initiation Exchange Fingerprinting             #
#                                                                    #
# Script Version: v2.0 November 2026                                 #
# Authors: Ben Reardon (breardon@salesforce.com, @benreardon)        #
#        : Jeff Atkinson (jatkinson@salesforce.com)                  #
#        : John Althouse (jalthouse@salesforce.com)                  #
# Description:  This Zeek script appends hassh data to ssh.log       #
#               by enumerating the SSH_MSG_KEXINIT packets sent      #
#               as clear text between the client and server as part  #
#               of the negotiation of an SSH connection.             #
#                                                                    #
# Copyright (c) 2018, salesforce.com, inc.                           #
# All rights reserved.                                               #
# SPDX-License-Identifier: BSD-3-Clause                              #
# For full license text, see the LICENSE file in the repo root or    #
# https://opensource.org/licenses/BSD-3-Clause                       #

@load base/protocols/ssh

module SSH;

export {
    ## Version of the hassh/hasshServer composition. ANY change in how the
    ## fingerprints are composed requires a version update.
    const hassh_version = "1.1" &redef;

    ## Log the raw algorithm strings the fingerprints are computed from.
    option hassh_log_algorithms = T;

    ## Log the host key algorithm lists (cshka / sshka). They are not part of
    ## the fingerprints but are useful context.
    option hassh_log_host_key_algorithms = T;

    ## Log each individual algorithm list (ckex, ceacts, cmacts, ccacts and
    ## skex, seastc, smastc, scastc).
    option hassh_log_components = F;
}

redef record SSH::Info += {
    hasshVersion:           string &log &optional;
    hassh:                  string &log &optional;
    hasshServer:            string &log &optional;

    # Client variables
    ckex:                   string &log &optional;
    cshka:                  string &log &optional;
    ceacts:                 string &log &optional;
    cmacts:                 string &log &optional;
    ccacts:                 string &log &optional;
    hasshAlgorithms:        string &log &optional;

    # Server variables
    skex:                   string &log &optional;
    sshka:                  string &log &optional;
    seastc:                 string &log &optional;
    smastc:                 string &log &optional;
    scastc:                 string &log &optional;
    hasshServerAlgorithms:  string &log &optional;
};

# Build Client Application fingerprint: md5(KEX;EACTS;MACTS;CACTS)
function get_hassh(c: connection, capabilities: SSH::Capabilities)
    {
    local ckex   = join_string_vec(capabilities$kex_algorithms, ",");
    local ceacts = join_string_vec(capabilities$encryption_algorithms$client_to_server, ",");
    local cmacts = join_string_vec(capabilities$mac_algorithms$client_to_server, ",");
    local ccacts = join_string_vec(capabilities$compression_algorithms$client_to_server, ",");
    local algorithms = string_cat(ckex, ";", ceacts, ";", cmacts, ";", ccacts);

    c$ssh$hasshVersion = hassh_version;
    c$ssh$hassh = md5_hash(algorithms);
    if ( hassh_log_algorithms )
        c$ssh$hasshAlgorithms = algorithms;
    if ( hassh_log_host_key_algorithms )
        c$ssh$cshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
    if ( hassh_log_components )
        {
        c$ssh$ckex = ckex;
        c$ssh$ceacts = ceacts;
        c$ssh$cmacts = cmacts;
        c$ssh$ccacts = ccacts;
        }
    }

# Build Server Application fingerprint: md5(KEX;EASTC;MASTC;CASTC)
function get_hasshServer(c: connection, capabilities: SSH::Capabilities)
    {
    local skex   = join_string_vec(capabilities$kex_algorithms, ",");
    local seastc = join_string_vec(capabilities$encryption_algorithms$server_to_client, ",");
    local smastc = join_string_vec(capabilities$mac_algorithms$server_to_client, ",");
    local scastc = join_string_vec(capabilities$compression_algorithms$server_to_client, ",");
    local algorithms = string_cat(skex, ";", seastc, ";", smastc, ";", scastc);

    c$ssh$hasshVersion = hassh_version;
    c$ssh$hasshServer = md5_hash(algorithms);
    if ( hassh_log_algorithms )
        c$ssh$hasshServerAlgorithms = algorithms;
    if ( hassh_log_host_key_algorithms )
        c$ssh$sshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
    if ( hassh_log_components )
        {
        c$ssh$skex = skex;
        c$ssh$seastc = seastc;
        c$ssh$smastc = smastc;
        c$ssh$scastc = scastc;
        }
    }

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
    {
    if ( ! c?$ssh )
        return;

    # Zeek releases before 2.6.0 reversed the client/server flag
    # (https://github.com/zeek/zeek/pull/191); this script needs Zeek >= 3.0.
    if ( capabilities$is_server )
        get_hasshServer(c, capabilities);
    else
        get_hassh(c, capabilities);
    }
