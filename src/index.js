#!/usr/bin/env node

'use strict'

process.umask(~0o600)

const x509 = require('x509.js')
const path = require('path')
const DNS = require('@google-cloud/dns');
const fs = require('fs-extra')
const {spawn} = require('child_process');
const exec = require('util').promisify(require('child_process').exec);

const args = require('yargs')
    .usage('$0 [args]')
    .options({
      'le-live-dir': {
        alias: 'l',
        demandOption: true
      },
      'tlsa-dir': {
        alias: 't',
        demandOption: true
      },
      'proto-port': {
        alias: 'p',
        'default': 'tcp:443'
      },
      'rollover-period': {
        alias: 'r',
        default: 3600 * 24
      },
      'project-id': {
        alias: 'i',
        demandOption: true
      },
      'zone-id': {
        alias: 'z',
        demandOption: true
      },
      'force': {
        alias: 'f',
        boolean: true
      },
      'force-deploy': {
        alias: 'd',
        boolean: true
      },
      'activation-hook': {
        alias: 'a'
      }
    })
    .help()
    .argv

async function main() {
  const liveCertPath = path.resolve(args['le-live-dir'], 'cert.pem')
  console.log('Cert path', liveCertPath)

  const liveCertBuffer = await fs.readFile(liveCertPath)
  const liveCert = x509.parseCert(liveCertBuffer);
  console.log(JSON.stringify(liveCert, null, 2))

  let sameCerts = false
  const activeCertRoot = path.resolve(args['tlsa-dir'], 'active', liveCert.subject.commonName)
  try {
    const activeCertPath = path.resolve(activeCertRoot, 'cert.pem')
    const activeCertBuffer = await fs.readFile(activeCertPath)
    sameCerts = Buffer.compare(liveCertBuffer, activeCertBuffer) === 0
  } catch(e) {
    console.log(e)
  }

  if (sameCerts && !args.force) {
    console.log('Certs are the same. Nothing to do.')
    process.exit(0)
  } else {
    console.log('Certs are not the same. Let\'s continue.')
  }

  const protoPorts = args['proto-port'].split(',').map(pair => pair.split(':')).map(([protocol, port]) => ({protocol, port}))
  console.log('proto-ports', protoPorts)


  const liveCertHash = await sha256Cert(liveCertPath)
  const tlsaRecords = generateTlsaRecords(liveCert.altNames, protoPorts, liveCertHash)

  console.log('tlsaRecords', tlsaRecords)

  let recordDeployStats = null
  try {
    recordDeployStats = await fs.stat(path.resolve(activeCertRoot, `.${liveCertHash}.json`))
  } catch(e) {
    console.log(e)
  }

  console.log('stats', recordDeployStats)

  if(recordDeployStats === null || args['force-deploy']) {
    console.log('No recordDeploy file found.')
    await deployRecords(tlsaRecords)
    await fs.ensureDir(activeCertRoot)
    await fs.writeJson(path.join(activeCertRoot, `.${liveCertHash}.json`), {date: new Date()})
  } else if (recordDeployStats.mtimeMs + parseInt(args['rollover-period'], 10) * 1000 < Date.now()) {
    console.log('recordDeploy file found and rollover period has passed.')
    await activateLiveCert(activeCertRoot, tlsaRecords)
  } else {
    console.log('recordDeploy file found. Waiting for rollover period to pass.')
    process.exit(0)
  }
}

function sha256Cert(certPath) {
  return new Promise((resolve, reject) => {
    let settled = false
    try {
      let hash = ""
      const der = spawn('openssl', ['x509', '-in', certPath, '-outform', 'DER'], {stdio: ["pipe", "pipe", process.stderr]})
      const sha256 = spawn('openssl', ['sha256'], {stdio: ["pipe", "pipe", process.stderr]})
      der.on('error', err => {
        if (!settled) {
          settled = true
          reject(err)
        }
      })
      sha256.on('error', err => {
        if (!settled) {
          settled = true
          reject(err)
        }
      })
      sha256.stdout.setEncoding('utf8')
      sha256.stdout.on('data', data => {
        hash += data
      })
      sha256.stdout.on('end', () => {
        if (!settled) {
          settled = true
          resolve(hash.slice(hash.indexOf('=') + 2, -1))
        }
      })
      der.stdout.pipe(sha256.stdin)

    } catch(e) {
      if (!settled) {
        settled = true
        reject(e)
      }
    }
  })
}

function generateTlsaRecords(domains, protoPorts, hash) {
  const records = []
  for (const domain of domains) {
    for (const {protocol, port} of protoPorts) {
      records.push({name: `_${port}._${protocol}.${domain}`, domain, protocol, port, hash})
    }
  }
  return records
}

async function deployRecords(tlsaRecords) {
  const projectId = args['project-id']
  const dns = new DNS({
    projectId: projectId,
  })
  const zone = dns.zone(args['zone-id'])

  const change = {add: [], delete: []}

  for(const [tlsaRecord, recordPromise] of tlsaRecords.map(record => [record, zone.getRecords({type: 'TLSA', name: `${record.name}.`})])) {
    const data = `1 0 1 ${tlsaRecord.hash}`
    const [records] = await recordPromise
    if(records.length > 0) {
      const oldRecord = records[0]
      if(oldRecord.data.indexOf(data) === -1) {
        const newRecord = zone.record('TLSA', {name: `${tlsaRecord.name}.`, data: [...oldRecord.data, data], ttl: 300})
        change.add.push(newRecord)
        change.delete.push(oldRecord)
      }
    } else {
      const newRecord = zone.record('TLSA', {name: `${tlsaRecord.name}.`, data: [data], ttl: 300})
      change.add.push(newRecord)
    }
  }

  if(change.add.length > 0 || change.delete.length > 0) {
    const [, response] = await zone.createChange(change)
    console.log('response', response)
  } else {
    console.log('No changes.')
  }

}


async function activateLiveCert(activeCertRoot, tlsaRecords) {
  const activeCertPath = path.resolve(activeCertRoot, 'cert.pem')
  let activeCertHash = null
  try {
    await fs.access(activeCertPath, fs.constants.F_OK | fs.constants.W_OK)
    activeCertHash = await sha256Cert(activeCertPath)
  } catch(e) {
    console.log(e)
  }
  const liveCertRoot = args['le-live-dir']
  const certLinkPromise = fs.readlink(path.resolve(liveCertRoot, 'cert.pem'))
  const chainLinkPromise = fs.readlink(path.resolve(liveCertRoot, 'chain.pem'))
  const fullchainLinkPromise = fs.readlink(path.resolve(liveCertRoot, 'fullchain.pem'))
  const privkeyLinkPromise = fs.readlink(path.resolve(liveCertRoot, 'privkey.pem'))

  const certUnlinkPromise = fs.unlink(path.resolve(activeCertRoot, 'cert.pem')).catch(err => {console.log(err)})
  const chainUnlinkPromise = fs.unlink(path.resolve(activeCertRoot, 'chain.pem')).catch(err => {console.log(err)})
  const fullchainUnlinkPromise = fs.unlink(path.resolve(activeCertRoot, 'fullchain.pem')).catch(err => {console.log(err)})
  const privkeyUnlinkPromise = fs.unlink(path.resolve(activeCertRoot, 'privkey.pem')).catch(err => {console.log(err)})

  await certUnlinkPromise;
  fs.ensureSymlink(path.resolve(liveCertRoot, await certLinkPromise), path.resolve(activeCertRoot, 'cert.pem'))
  
  await chainUnlinkPromise;
  fs.ensureSymlink(path.resolve(liveCertRoot, await chainLinkPromise), path.resolve(activeCertRoot, 'chain.pem'))

  await fullchainUnlinkPromise;
  fs.ensureSymlink(path.resolve(liveCertRoot, await fullchainLinkPromise), path.resolve(activeCertRoot, 'fullchain.pem'))

  await privkeyUnlinkPromise;
  fs.ensureSymlink(path.resolve(liveCertRoot, await privkeyLinkPromise), path.resolve(activeCertRoot, 'privkey.pem'))

  if(typeof args['activation-hook'] === 'string') {
    try {
      console.log('Executing activation hook...')
      const {stdout, stderr} = await exec(args['activation-hook'])
      console.log(stdout)
      console.error(stderr)
      console.log('Done.')
    } catch (e) {
      console.log('Activation hook exited with a non-zero exit code. Stopping.')
      console.log(e)
      process.exit(0)
    }
  }

  const projectId = args['project-id']
  const dns = new DNS({
    projectId: projectId,
  })
  const zone = dns.zone(args['zone-id'])
  const change = {add: [], delete: []}

  for(const [tlsaRecord, recordPromise] of tlsaRecords.map(record => [record, zone.getRecords({type: 'TLSA', name: `${record.name}.`})])) {
    const newData = `1 0 1 ${tlsaRecord.hash}`
    let oldData = null
    if (activeCertHash !== null) {
      oldData = `1 0 1 ${activeCertHash}`
    }
    const [records] = await recordPromise
    if(records.length > 0) {
      const oldRecord = records[0]
      const dataArray = [...oldRecord.data]

      if(oldData !== null) {
        const oldDataIndex = dataArray.indexOf(oldData)
        if(oldDataIndex !== -1) {
          dataArray.splice(oldDataIndex, 1)
        }
      }

      if(dataArray.indexOf(newData) === -1) {
        dataArray.push(newData)
      }
      
      const newRecord = zone.record('TLSA', {name: `${tlsaRecord.name}.`, data: dataArray, ttl: 300})
      change.add.push(newRecord)
      change.delete.push(oldRecord)
    } else {
      const newRecord = zone.record('TLSA', {name: `${tlsaRecord.name}.`, data: [newData], ttl: 300})
      change.add.push(newRecord)
    }
  }

  if(change.add.length > 0 || change.delete.length > 0) {
    const [, response] = await zone.createChange(change)
    console.log('response', response)
  } else {
    console.log('No changes.')
  }
}

main()
