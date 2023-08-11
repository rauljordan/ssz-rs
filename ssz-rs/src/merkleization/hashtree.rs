use crate::merkleization::{MerkleizationError, BYTES_PER_CHUNK, CONTEXT};

fn sparse_hash_tree(
    hash_tree: &mut [u8],
    chunks: &mut [u8],
    depth: usize,
) -> Result<(), MerkleizationError> {
    let byte_length = chunks.len();
    if depth == 0 {
        if hash_tree.len() < byte_length {
            return Err(MerkleizationError::InvalidInput);
        }
        hash_tree[..byte_length].copy_from_slice(&chunks[..byte_length]);
        return Ok(());
    }
    let mut first = 0;
    let last = hash_first_layer(hash_tree, chunks)?;

    for height in 1..depth {
        let dist = (last - first) / BYTES_PER_CHUNK;
        let next_first = last;
        if dist > 1 {
            let input = &hash_tree[first..];
            let output = &mut hash_tree[last..];
            hash(output, input, dist / 2);
        }
        if dist & 1 == 1 {
            let input = &hash_tree[(next_first - BYTES_PER_CHUNK)..];
            let output = &mut hash_tree[last..];
            hash_2_chunks(output, input, &CONTEXT[height]);
        }
        first = next_first;
    }
    Ok(())
}

// TODO: Figure out proper return value of this function.
fn hash_first_layer(hash_tree: &mut [u8], chunks: &mut [u8]) -> Result<usize, MerkleizationError> {
    let chunk_count = (chunks.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
    if chunk_count == 1 {
        return Err(MerkleizationError::InvalidInput);
    }
    let left_over_bytes = chunks.len() % BYTES_PER_CHUNK != 0;
    // if there are left over bytes we can't hash in-place.
    if chunk_count & 1 == 0 && !left_over_bytes {
        hash(hash_tree, chunks, chunk_count / 2);
        return Ok(0);
    }
    // We had some left over bytes or an odd number of chunks hash as much as we can without copying.
    let first_blocks = (chunk_count - 1) / 2;
    if first_blocks != 0 {
        hash(hash_tree, chunks, first_blocks);
    }
    // hash the last two chunks copying them>
    let offset = first_blocks * 2 * BYTES_PER_CHUNK;
    let mut last_chunk = [0u8; 2 * BYTES_PER_CHUNK];
    let src = &chunks[offset..offset + (chunks.len() - offset)];
    last_chunk[..src.len()].copy_from_slice(src);
    hash(hash_tree, &mut last_chunk, 1);
    Ok(0)
}

/// Helper to hash two non-necessarily consecutive chunks of 32 bytes.
///
/// Does not check bounds, undefined behavior if the two ranges do not have at least 32 bytes.
fn hash_2_chunks(output: &mut [u8], first: &[u8], second: &[u8]) {
    const CHUNK_SIZE: usize = 32; // Assuming chunks are 32 bytes based on the comment
    let mut sum = [0u8; 2 * CHUNK_SIZE];

    sum[..CHUNK_SIZE].copy_from_slice(&first[..CHUNK_SIZE]);
    sum[CHUNK_SIZE..].copy_from_slice(&second[..CHUNK_SIZE]);

    hash(output, &mut sum, 1)
}

fn hash(output: &mut [u8], input: &[u8], count: usize) {}

#[cfg(test)]
mod test {
    #[test]
    fn test_hash_first_layer() {}
}
