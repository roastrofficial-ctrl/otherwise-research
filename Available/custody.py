"""Capability negotiation is compatibility checking, not proof of honest custody."""
from .proofs import require

LAB_REQUIREMENTS={'operation':'reconstruct-aes-128-gcm','owner_disarm':True,
                  'verified_certificate':True,'simulated_delivery':True,
                  'cryptographic_policy_enforcement':False}

def compatible(capabilities,requirements):
    require(set(capabilities)==set(LAB_REQUIREMENTS),'custody capability schema')
    require(all(capabilities.get(k)==v for k,v in requirements.items()),'custody security/capability mismatch')
    return True

class StaticShareCustody:
    capabilities=dict(LAB_REQUIREMENTS)
    def authorise(self,certificate,retained):
        from .proofs import release
        return release(certificate,retained)


from typing import Protocol,runtime_checkable

@runtime_checkable
class CustodyProvider(Protocol):
    """Policy gate for the pinned operation; material persistence stays in provider service.
    A future cryptographic provider must use a distinct advertised enforcement capability.
    """
    capabilities: dict
    def authorise(self,certificate:dict,retained:list)->dict: ...


class NodeCheckedStaticShareCustody:
    """Replaceable lab gate using the independent evaluator; same weak custody model."""
    capabilities=dict(LAB_REQUIREMENTS)
    def authorise(self,certificate,retained):
        import subprocess
        from Engine.protocol import canonical
        from Bounded.wire import strict_json
        p=subprocess.run(['node','Verifier/available.mjs'],input=canonical({'kind':'release','object':certificate,'retained':retained}),capture_output=True)
        result=strict_json(p.stdout)
        require(p.returncode==0 and result.pop('ok',False),'custody provider rejects certificate')
        return result
