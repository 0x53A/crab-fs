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

