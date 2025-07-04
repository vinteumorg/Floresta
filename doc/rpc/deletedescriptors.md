 # `deletedescriptors`

 From a given array of DescriptorId's, find and delete the identified ones.

 ## Arguments

 * ids - json array containing the descriptor ids.

```json5
 [
     {                                    (json object)
        "hash": "str",                    A descriptor identified by its double sha256 of the derived miniscript.
     },
     {                                    (json object)
         "label": "str",                  A descriptor identified by an arbitrary label. Searching by arbitrary labels can be expensive as it isnt indexed by it.
     },
     {                                    (json object)
         "miniscript": "str",             A descriptor identified by its miniscript.
     },
 ]
```

 * pull - The boolean that defines whether to pull the deleted descriptors or not. (default=false)

 ## Returns

 ### Ok Response

     - Returns the deleted descriptors if specified to do it.

 ### Error Enum [`floresta_common::descriptor_internals::DescriptorError`]

 Specified descriptor was not found.
 DescriptorNotFound,

 ## Usage Examples

 ```bash
    floresta-cli deletedescriptors [{"hash": "ebd042345b560280c7d676a9d4743fc1a3016017ca99cb6650da957be1ca4437"}, {"label": "my_vinteum_donation"}] --pull

    floresta-cli deletedescriptors [{"miniscript": "ebd042345b560280c7d676a9d4743fc1a3016017ca99cb6650da957be1ca4437"}, {"label": "my_vinteum_donation"}] --pull

    floresta-cli deletedescriptors [{"miniscript": "ebd042345b560280c7d676a9d4743fc1a3016017ca99cb6650da957be1ca4437"}] 
 ```

 ## Notes

 - A DescriptorId is an internal enum type that we use to facilitate descriptors handling.
 - Related Methods: "importdescriptors", "listdescriptors"
