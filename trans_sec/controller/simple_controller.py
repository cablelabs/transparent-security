# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json
import logging

import trans_sec.p4runtime_lib.bmv2
import trans_sec.p4runtime_lib.helper

logger = logging.getLogger('simple_controller')


class ConfException(Exception):
    pass


def program_switch(addr, device_id, p4info_fpath, bmv2_json_fpath,
                   proto_dump_fpath, table_entries=None):
    p4info_helper = trans_sec.p4runtime_lib.helper.P4InfoHelper(p4info_fpath)

    sw = trans_sec.p4runtime_lib.bmv2.Bmv2SwitchConnection(
        address=addr, device_id=device_id,
        proto_dump_file=proto_dump_fpath)

    try:
        sw.master_arbitration_update()

        logger.info("Setting pipeline config with file - [%s]",
                    bmv2_json_fpath)
        sw.set_forwarding_pipeline_config(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=bmv2_json_fpath)

        if table_entries:
            for entry in table_entries:
                insert_table_entry(sw, entry, p4info_helper)
    finally:
        sw.shutdown()


def insert_table_entry(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match')  # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action')  # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found

    table_entry = p4info_helper.build_table_entry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)

    logger.info('Writing table entry - [%s]', table_entry)
    sw.write_table_entry(table_entry)


# object hook for JSON library, use str instead of unicode object
# https://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-of-unicode-from-json
def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify),
                    ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value,
                                                       ignore_dicts=True)
            for key, value in data.items()
        }
    # if it's anything else, return it in its original form
    return data


def table_entry_to_string(flow):
    if 'match' in flow:
        match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for
                     match_name in
                     flow['match']]
        match_str = ', '.join(match_str)
    elif 'default_action' in flow and flow['default_action']:
        match_str = '(default action)'
    else:
        match_str = '(any)'
    params = ['%s=%s' % (param_name, str(flow['action_params'][param_name]))
              for param_name in
              flow['action_params']]
    params = ', '.join(params)
    return "%s: %s => %s(%s)" % (
        flow['table'], match_str, flow['action_name'], params)
