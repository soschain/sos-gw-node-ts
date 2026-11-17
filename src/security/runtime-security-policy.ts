/** Demo is an explicit local profile, never a synonym for Test Network. */
export function isLocalDemoSecurityMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const deployment = [env.NODE_ENV, env.DEPLOYMENT_ENV].map(value => String(value || '').toLowerCase());
  return env.SECURITY_MODE === 'demo'
    && String(env.NETWORK_MODE || 'test').toLowerCase() === 'test'
    && !deployment.some(value => ['production', 'prod', 'staging'].includes(value));
}

export function allowsInsecureDemoBearer(env: NodeJS.ProcessEnv = process.env): boolean {
  return isLocalDemoSecurityMode(env) && /^(true|1|yes|enabled)$/i.test(String(env.DEMO_ALLOW_INSECURE_BEARER || ''));
}

/** Rejects demo in network, staging and production profiles before startup. */
export function assertRuntimeSecurityProfile(env: NodeJS.ProcessEnv = process.env): void {
  if (env.SECURITY_MODE === 'demo' && !isLocalDemoSecurityMode(env)) {
    throw new Error('SECURITY_MODE=demo requires an explicit local demonstration profile.');
  }
}

export type RuntimeSecurityConfiguration=Readonly<{
  securityMode?:string;
  networkMode?:string;
  nodeEnv?:string;
  deploymentEnv?:string;
}>;
/** Evaluate actual deployment context and trusted configuration together; neither may hide a stricter environment. */
export function isLocalDemoSecurityModeForConfiguration(config:RuntimeSecurityConfiguration,env:NodeJS.ProcessEnv=process.env):boolean{
  const actualDeployment=[env.NODE_ENV,env.DEPLOYMENT_ENV].map(value=>String(value||'').trim().toLowerCase());
  const actualNetwork=String(env.NETWORK_MODE||'').trim().toLowerCase();
  if(actualDeployment.some(value=>['production','prod','staging'].includes(value))||(actualNetwork&&actualNetwork!=='test'))return false;
  return isLocalDemoSecurityMode({...env,SECURITY_MODE:config.securityMode??env.SECURITY_MODE,NETWORK_MODE:(config.networkMode??env.NETWORK_MODE)?.trim().toLowerCase(),NODE_ENV:(config.nodeEnv??env.NODE_ENV)?.trim().toLowerCase(),DEPLOYMENT_ENV:(config.deploymentEnv??env.DEPLOYMENT_ENV)?.trim().toLowerCase()});
}
/** Reject conflicting deployment/configuration Demo profiles before composition or serving requests. */
export function assertConfiguredRuntimeSecurityProfile(config:RuntimeSecurityConfiguration,env:NodeJS.ProcessEnv=process.env):void{
  if([config.securityMode,env.SECURITY_MODE].some(value=>value==='demo')&&!isLocalDemoSecurityModeForConfiguration(config,env)){
    throw new Error('SECURITY_MODE=demo requires an explicit local demonstration profile in both deployment and configuration.');
  }
}
