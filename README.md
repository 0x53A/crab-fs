A toy encryped deduplicating filesystem based on the 'simple' example of https://github.com/cberner/fuser


Goals:

 a

 * content addressed
 * and therefore deduplicating
 * & encrypted

 Filesystem.

 -------------


Architecture:

This is an overlay filesystem, that is, it will write to disk somewhere. Long-term it would be interesting to directly add a S3 (and other) backend, but for now, you would need to first mount your remote filesystem, and then map this filesystem on top.

All file contents are saved to a subfolder 'c'. There are two kinds of content, one that is content addressed, and one that is 'named' (a uuid). While a file write is in progress, the content is 'named' and directly mutated. After the file was closed, it will be hashed, and moved to be content addressed. This provides for deduplication.

In the near term, I'd like to add chunking, so that also similar files can be deduplicated instead of just exactly equal ones.

The backend folder structure is flat - there is one directory for each directory, sub-directories just link back out to this root directory.

A 'directory' is a single serialized structure containing the meta-data of all entries.

