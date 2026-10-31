import { digest } from '../core/utils.js';

export const XAVI_DISTRIBUTION_LICENSE='MIT OR Apache-2.0';
export const APPROVED_DISTRIBUTION_LICENSES=Object.freeze([XAVI_DISTRIBUTION_LICENSE]);
export const APPROVED_DEPENDENCY_LICENSES=Object.freeze(['MIT','Apache-2.0',XAVI_DISTRIBUTION_LICENSE]);

const dependencyLicenseAllowed=license=>APPROVED_DEPENDENCY_LICENSES.includes(String(license));

function normalizeDependencies(rows=[]){
  if(!Array.isArray(rows))throw new TypeError('dependencies must be an array');
  return rows.map((row,index)=>{
    const name=String(row?.name||'').trim();
    const license=String(row?.license||'').trim();
    if(!name)throw new Error(`distribution image rejected: dependency ${index} name required`);
    if(!dependencyLicenseAllowed(license))throw new Error(`distribution image rejected: dependency ${name} has unapproved license ${license||'<missing>'}`);
    return Object.freeze({
      name,
      version:String(row?.version||'').trim(),
      license,
      source:String(row?.source||'').trim(),
      contentDigest:String(row?.contentDigest||'').trim(),
    });
  });
}

export class FirstPartyImageRegistry{
  constructor(xavi=null){this.xavi=xavi&&xavi.ledger?xavi:null;this.images=new Map();}
  async register({
    id,
    version='0.0.0',
    license=XAVI_DISTRIBUTION_LICENSE,
    firstParty=true,
    sourceDigest=null,
    contentDigest=null,
    bytes=null,
    buildRecipe='',
    capabilities=[],
    dependencies=[],
    metadata={},
  }={}){
    if(!id)throw new TypeError('image id required');
    if(firstParty!==true)throw new Error('distribution image rejected: firstParty must be true');
    if(String(license)!==XAVI_DISTRIBUTION_LICENSE)throw new Error(`distribution image rejected: image license must be ${XAVI_DISTRIBUTION_LICENSE}`);
    if(!sourceDigest)throw new Error('distribution image rejected: source digest required');
    let resolvedDigest=contentDigest;
    if(!resolvedDigest&&bytes!=null)resolvedDigest=await digest(bytes);
    if(!resolvedDigest)throw new Error('distribution image rejected: content digest required');
    const deps=normalizeDependencies(dependencies);
    const row=Object.freeze({
      schema:'xavi-wasm-guest-image/v1',
      id:String(id),
      version:String(version||'0.0.0'),
      license:XAVI_DISTRIBUTION_LICENSE,
      firstParty:true,
      sourceDigest:String(sourceDigest),
      contentDigest:String(resolvedDigest),
      buildRecipe:String(buildRecipe||''),
      capabilities:Object.freeze([...new Set((capabilities||[]).map(String))]),
      dependencies:Object.freeze(deps),
      metadata:Object.freeze({...metadata}),
      registeredAt:Date.now(),
    });
    this.images.set(row.id,row);
    if(this.xavi)await this.xavi.ledger.append('sandbox-image-approved',{
      schema:row.schema,
      id:row.id,
      version:row.version,
      license:row.license,
      firstParty:true,
      sourceDigest:row.sourceDigest,
      contentDigest:row.contentDigest,
      buildRecipe:row.buildRecipe,
      capabilities:[...row.capabilities],
      dependencyInventory:row.dependencies.map(({name,version,license,contentDigest})=>({name,version,license,contentDigest})),
    });
    return row;
  }
  get(id){return this.images.get(String(id))||null;}
  list(){return [...this.images.values()];}
  require(id){const row=this.get(id);if(!row)throw new Error(`sandbox image not approved: ${id}`);return row;}
}
