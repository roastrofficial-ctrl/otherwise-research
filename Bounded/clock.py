"""Conservative observation clock. Samples UTC against monotonic elapsed time.
The source and persistent state live with the independent witness, not the app.
"""
import time
import uuid


class Clock:
    def __init__(self, state=None, *, wall=time.time_ns, mono=time.monotonic_ns,
                 tolerance_ms=1000, max_gap_ms=30000, radius_ms=1000, test=False):
        self.wall, self.mono = wall, mono
        self.tolerance, self.max_gap, self.radius = tolerance_ms, max_gap_ms, radius_ms
        self.test = test
        self.session = uuid.uuid4().hex
        self.state = dict(state or {})
        if state and not test:
            self.state['healthy'] = False  # monotonic process/session continuity was lost
            self.state['reason'] = 'restart requires recovery'
        self.last = None
        self.anchor = None

    def sample(self):
        if self.test:
            return dict(self.state or {'lower':0,'upper':0,'healthy':True,'reason':'test clock'})
        wall, mono = self.wall()//1_000_000, self.mono()//1_000_000
        healthy = self.state.get('healthy', True)
        reason = self.state.get('reason', 'bounded local observation')
        if self.last:
            dw, dm = wall-self.last[0], mono-self.last[1]
            cumulative=(wall-self.anchor[0])-(mono-self.anchor[1])
            if dm < 0 or abs(dw-dm)>self.tolerance or abs(cumulative)>self.tolerance or dm>self.max_gap or wall<self.last[0]:
                healthy=False; reason='discontinuity or observation gap'
        if self.state and wall//1000 < self.state['lower']:
            healthy=False; reason='restored or rolled-back wall clock'
        lower=(wall-self.radius)//1000
        upper=(wall+self.radius+999)//1000
        self.state={'lower':max(lower,self.state.get('lower',lower)),
                    'upper':max(upper,self.state.get('upper',upper)),
                    'healthy':healthy,'reason':reason}
        if self.anchor is None: self.anchor=(wall,mono)
        self.last=(wall,mono)
        return dict(self.state)

    def advance(self, now, *, healthy=True):
        if not self.test: raise ValueError('test clock disabled')
        if type(now) is not int or now < self.state.get('lower',0): raise ValueError('clock rollback')
        self.state={'lower':now,'upper':now,'healthy':bool(healthy),'reason':'controlled fault injection'}
        return self.sample()

    def recover(self):
        # Caller must validate an owner-signed RECOVERED event and fresh grace.
        self.sample()
        self.anchor=self.last
        self.state['healthy']=True
        self.state['reason']='explicit recovery'
