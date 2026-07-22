import { Secp256k1Keypair, P256Keypair, type Keypair } from '@atproto/crypto'
import {
  Repo,
  MemoryBlockstore,
  WriteOpAction,
  type RecordCreateOp,
} from '@atproto/repo'
import { jwks } from './DemoKeys.js';
import { RepoKeyPairImpl } from './RepoKeyPairImpl.js';
import { decode } from "@ipld/dag-cbor";
import { CarWriter } from "@ipld/car";
import { writeFile } from "node:fs/promises";

// A small, valid record-key alphabet to hand out unique rkeys below.
// (Real atproto rkeys are usually TIDs, but any string matching the
// record-key syntax works fine for this kind of experimentation.)
const RKEY_SUFFIXES = 'abcdefghij'.split('')

async function main() {

  const storage = new MemoryBlockstore()

  const entries: { did: string; repo: Repo; rkey: string }[] = []

  for (let i = 0; i < jwks.length; i++) {
    const keypair = new RepoKeyPairImpl(jwks[i]);
    const did = keypair.did()
    const rkey = `3k2akfd3f2b2${RKEY_SUFFIXES[i]}`

    // create repo

    const initialWrites: RecordCreateOp[] = [
      {
        action: WriteOpAction.Create,
        collection: 'app.bsky.feed.post',
        rkey,
        record: {
          $type: 'app.bsky.feed.post',
          text: `Record #${i + 1}, signed by ${did}`,
          createdAt: new Date().toISOString(),
        },
      },
    ]

    const repo = await Repo.create(storage, did, keypair, initialWrites)

    console.log(`[${i + 1}/${jwks.length}] DID: ${did} (${keypair.jwtAlg()})`)
    console.log(`CID: ${repo.cid.toString()}`)
    const content: Uint8Array = storage.blocks.get(repo.cid)
    const hex = Buffer.from(content).toString("hex")
    const obj = decode(content);
    obj.sig = Buffer.from(obj.sig).toString("hex");
    console.log(`HEX: ${hex}`)
    console.log(`OBJ: ${JSON.stringify(obj)}`)
    console.log(``)

    entries.push({ did, repo, rkey })
  }

  // read every record back out and confirm it against its own repo/DID.

  console.log('\nAll records:')
  for (const { did, repo, rkey } of entries) {
    const record = await repo.getRecord('app.bsky.feed.post', rkey)
    console.log(`[${did}] --> `, record)
  }

  // write storage

  saveBlockstoreToCar(storage, "./output.car")
}

async function saveBlockstoreToCar(blockstore: any, path: string, roots: any[]) {
  const { writer, out } = await CarWriter.create(roots);

  const chunks: Uint8Array[] = [];
  const collecting = (async () => {
    for await (const chunk of out) {
      chunks.push(chunk);
    }
  })();

  for (const [cid, bytes] of blockstore.blocks) {
    await writer.put({ cid, bytes });
    console.log(`Wrote block with CID: [${cid}], ${bytes.length} bytes`)
  }

  await writer.close();
  await collecting;

  await writeFile(path, Buffer.concat(chunks));
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
