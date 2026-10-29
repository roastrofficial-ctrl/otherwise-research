"""Independent finite two-value/two-view safety exploration, not a proof of code.
Abstracts valid signatures, values and durable single votes; enumerates delivery
subsets of prepared proofs/commits and view-change quorum compositions.
"""
import itertools,json
N=4;honest=(0,1,2);values=('RELEASE','DISARM');checked=0;unsafe=None
for byz in range(N):
    H=tuple(i for i in range(N) if i!=byz)
    for prep in itertools.product((None,*values),repeat=3):
        prepares=dict(zip(H,prep));possible=[v for v in values if sum(prepares[i]==v for i in H)>=2]
        # A Byzantine may sign both, but two conflicting prepare quorums cannot exist.
        assert len(possible)<=1
        for delivered in itertools.product((False,True),repeat=3):
            locks={i:(possible[0] if possible and delivered[j] else None) for j,i in enumerate(H)}
            old={v for v in possible if sum(locks[i]==v for i in H)>=2}
            for vc in itertools.combinations(range(N),3):
                learned={locks[i] for i in vc if i!=byz and locks[i] is not None}
                # Byzantine may omit a proof or report a genuinely possible prepared proof.
                for bproof in (None,*possible):
                    known=set(learned)
                    if byz in vc and bproof is not None:known.add(bproof)
                    assert len(known)<=1
                    choices=list(known) if known else list(values)
                    for chosen in choices:
                        for next_delivered in itertools.product((False,True),repeat=3):
                            new={chosen} if sum(next_delivered)>=2 else set()
                            assert not(old and new and old!=new)
                            checked+=1
                    # Deliberately broken view change that ignores prepared evidence.
                    if old and known and unsafe is None:
                        bad=next(v for v in values if v not in old);unsafe={'byzantine':byz,'view0_prepares':prepares,'prepared_delivered':locks,'old_commit':list(old),'view_change_members':vc,'highest_prepared':list(known),'broken_new_commit':bad}
print(json.dumps({'method':'finite exhaustive abstraction','views':2,'values':2,'replicas':4,'byzantine_positions':4,'transitions_checked':checked,'conflicting_commits':0,'unsafe_variant_counterexample':unsafe,'assumptions':['unforgeable signatures','honest per-view no-double-vote','COMMIT requires persisted prepared proof','view-change carries known prepared proof','no old-view voting after advance'],'not_modelled':['crypto/canonical encoding','implementation refinement','FS/clock/network timers','arbitrary views','membership change','global rollback','full liveness']},indent=2))
