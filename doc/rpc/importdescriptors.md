 # `importdescriptors`

 Imports the given descriptor requests into the watch-only wallet.

 ## Arguments

 * `requests` - A json Object that describes some meta-data about a descriptor and how to derive it.

 A Descriptor Request

 ```json5
 [
     {                                    (json object)
         "desc": "str",                     (string, required) Descriptor to import.

         "active": bool,                    (boolean, optional, default=false) Set this descriptor to be the active descriptor for the corresponding output type/externality.

         "range": n or [n,n],               (numeric or array) If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import.

         "next_index": n,                   (numeric) If a ranged descriptor is set to active, this specifies the next index to generate addresses from.

         "timestamp": timestamp | "now" | "full",    (integer / string, required) Time from which to start rescanning the blockchain for this descriptor, in UNIX epoch time. Use the string "now" to substitute the current synced blockchain time. "now" can be specified to bypass scanning, for outputs which are known to never have been used, and 0 or "full" can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp of all descriptors being imported will be scanned.

         "internal": bool,                  (boolean, optional, default=false) Whether matching outputs should be treated as not incoming payments (e.g. change).

         "label": "str",                    (string, optional, default='') Label to assign to the address.

     },
 ]
```
 ## Returns

 ### Ok Response

     - Returns a Boolean indicating whether the request was successful.

 ### Error Enum [`floresta_common::descriptor_internals::DescriptorError`]

 These are the expected errors and cases;

 Error while deriving the descriptors.
 DerivationError(ConversionError),

 Could not parse the descriptor
 InvalidDescriptor,

 The descriptors script may be an invalid one.
 Miniscript(miniscript::Error),

 ## Usage Examples

 ```bash
     floresta-cli importdescriptors '[{ "desc": "pkh(02c6...)", "timestamp": 0, "internal": true, "label": "my_vinteum_donation_change" }, { "desc": "pkh(02c6...)", "label": "my_vinteum_donation", "timestamp": now }]'
 ```

 ## Notes

 - A descriptor request may yield more than one descriptor but, they are all deduped before being added to the wallet, the comparison factor is the descriptors miniscript.
 - While entering more than one request the timestamp can be overridden by another request. The priority is Full > Ignore > SpecifiedTime  (a lesser one) > SpecifiedTime.
 - If the node is during its IBD phase the rescan request will be skipped but the descriptor will be added successfully. You might see the warning in the node logs and rescan later with "rescanblockchain"
 - Related RPC methods "deletedescriptor", "listdescriptors"