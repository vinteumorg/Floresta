 # `listdescriptors`

 List the wallet descriptors

 ## Returns

 ### Ok Response

     - Prints the cached descriptors.

 ## Usage Examples

 ```bash
     floresta-cli listdescriptors
 ```

 ## Notes

 - The case for error will panic and shutdown the node since it'll probably represent a memory corruption
 - Related Methods: "importdescriptors", "deletedescriptors".