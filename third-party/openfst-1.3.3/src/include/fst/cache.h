// cache.h

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright 2005-2010 Google, Inc.
// Author: riley@google.com (Michael Riley)
//
// \file
// An Fst implementation that caches FST elements of a delayed
// computation.

#ifndef FST_LIB_CACHE_H__
#define FST_LIB_CACHE_H__

#include <vector>
using std::vector;
#include <list>

#include <fst/vector-fst.h>


DECLARE_bool(fst_default_cache_gc);
DECLARE_int64(fst_default_cache_gc_limit);

namespace fst {

struct CacheOptions {
  bool gc;          // enable GC
  size_t gc_limit;  // # of bytes allowed before GC

  CacheOptions(bool g, size_t l) : gc(g), gc_limit(l) {}
  CacheOptions()
      : gc(FLAGS_fst_default_cache_gc),
        gc_limit(FLAGS_fst_default_cache_gc_limit) {}
};

// A CacheStateAllocator allocates and frees CacheStates
// template <class S>
// struct CacheStateAllocator {
//   S *Allocate(StateId s);
//   void Free(S *state, StateId s);
// };
//

// A simple allocator class, can be overridden as needed,
// maintains a single entry cache.
template <class S>
struct DefaultCacheStateAllocator {
  typedef typename S::Arc::StateId StateId;

  DefaultCacheStateAllocator() : mru_(NULL) { }

  ~DefaultCacheStateAllocator() {
    delete mru_;
  }

  S *Allocate(StateId s) {
    if (mru_) {
      S *state = mru_;
      mru_ = NULL;
      state->Reset();
      return state;
    }
    return new S();
  }

  void Free(S *state, StateId s) {
    if (mru_) {
      delete mru_;
    }
    mru_ = state;
  }

 private:
  S *mru_;
};

// VectorState but additionally has a flags data member (see
// CacheState below). This class is used to cache FST elements with
// the flags used to indicate what has been cached. Use HasStart()
// HasFinal(), and HasArcs() to determine if cached and SetStart(),
// SetFinal(), AddArc(), (or PushArc() and SetArcs()) to cache. Note
// you must set the final weight even if the state is non-final to
// mark it as cached. If the 'gc' option is 'false', cached items have
// the extent of the FST - minimizing computation. If the 'gc' option
// is 'true', garbage collection of states (not in use in an arc
// iterator and not 'protected') is performed, in a rough
// approximation of LRU order, when 'gc_limit' bytes is reached -
// controlling memory use. When 'gc_limit' is 0, special optimizations
// apply - minimizing memory use.

template <class S, class C = DefaultCacheStateAllocator<S> >
class CacheBaseImpl : public VectorFstBaseImpl<S> {
 public:
  typedef S State;
  typedef C Allocator;
  typedef typename State::Arc Arc;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::StateId StateId;

  using FstImpl<Arc>::Type;
  using FstImpl<Arc>::Properties;
  using FstImpl<Arc>::SetProperties;
  using VectorFstBaseImpl<State>::NumStates;
  using VectorFstBaseImpl<State>::Start;
  using VectorFstBaseImpl<State>::AddState;
  using VectorFstBaseImpl<State>::SetState;
  using VectorFstBaseImpl<State>::ReserveStates;

  explicit CacheBaseImpl(C *allocator = 0)
      : cache_start_(false), nknown_states_(0), min_unexpanded_state_id_(0),
        cache_first_state_id_(kNoStateId), cache_first_state_(0),
        cache_gc_(FLAGS_fst_default_cache_gc),  cache_size_(0),
        cache_limit_(FLAGS_fst_default_cache_gc_limit > kMinCacheLimit ||
                     FLAGS_fst_default_cache_gc_limit == 0 ?
                     FLAGS_fst_default_cache_gc_limit : kMinCacheLimit),
        protect_(false) {
    allocator_ = allocator ? allocator : new C();
  }

  explicit CacheBaseImpl(const CacheOptions &opts, C *allocator = 0)
      : cache_start_(false), nknown_states_(0),
        min_unexpanded_state_id_(0), cache_first_state_id_(kNoStateId),
        cache_first_state_(0), cache_gc_(opts.gc), cache_size_(0),
        cache_limit_(opts.gc_limit > kMinCacheLimit || opts.gc_limit == 0 ?
                     opts.gc_limit : kMinCacheLimit),
        protect_(false) {
    allocator_ = allocator ? allocator : new C();
  }

  // Preserve gc parameters. If preserve_cache true, also preserves
  // cache data.
  CacheBaseImpl(const CacheBaseImpl<S, C> &impl, bool preserve_cache = false)
      : VectorFstBaseImpl<S>(), cache_start_(false), nknown_states_(0),
        min_unexpanded_state_id_(0), cache_first_state_id_(kNoStateId),
        cache_first_state_(0), cache_gc_(impl.cache_gc_), cache_size_(0),
        cache_limit_(impl.cache_limit_),
        protect_(impl.protect_) {
    allocator_ = new C();
    if (preserve_cache) {
      cache_start_ = impl.cache_start_;
      nknown_states_ = impl.nknown_states_;
      expanded_states_ = impl.expanded_states_;
      min_unexpanded_state_id_ = impl.min_unexpanded_state_id_;
      if (impl.cache_first_state_id_ != kNoStateId) {
        cache_first_state_id_ = impl.cache_first_state_id_;
        cache_first_state_ = allocator_->Allocate(cache_first_state_id_);
        *cache_first_state_ = *impl.cache_first_state_;
      }
      cache_states_ = impl.cache_states_;
      cache_size_ = impl.cache_size_;
      ReserveStates(impl.NumStates());
      for (StateId s = 0; s < impl.NumStates(); ++s) {
        const S *state =
            static_cast<const VectorFstBaseImpl<S> &>(impl).GetState(s);
        if (state) {
          S *copied_state = allocator_->Allocate(s);
          *copied_state = *state;
          AddState(copied_state);
        } else {
          AddState(0);
        }
      }
      VectorFstBaseImpl<S>::SetStart(impl.Start());
    }
  }

  ~CacheBaseImpl() {
    allocator_->Free(cache_first_state_, cache_first_state_id_);
    delete allocator_;
  }

  // Gets a state from its ID; state must exist.
  const S *GetState(StateId s) const {
    if (s == cache_first_state_id_)
      return cache_first_state_;
    else
      return VectorFstBaseImpl<S>::GetState(s);
  }

  // Gets a state from its ID; state must exist.
  S *GetState(StateId s) {
    if (s == cache_first_state_id_)
      return cache_first_state_;
    else
      return VectorFstBaseImpl<S>::GetState(s);
  }

  // Gets a state from its ID; return 0 if it doesn't exist.
  const S *CheckState(StateId s) const {
    if (s == cache_first_state_id_)
      return cache_first_state_;
    else if (s < NumStates())
      return VectorFstBaseImpl<S>::GetState(s);
    else
      return 0;
  }

  // Gets a state from its ID; add it if necessary.
  S *ExtendState(StateId s);

  void SetStart(StateId s) {
    VectorFstBaseImpl<S>::SetStart(s);
    cache_start_ = true;
    if (s >= nknown_states_)
      nknown_states_ = s + 1;
  }

  void SetFinal(StateId s, Weight w) {
    S *state = ExtendState(s);
    state->final = w;
    state->flags |= kCacheFinal | kCacheRecent | kCacheModified;
  }

  // AddArc adds a single arc to state s and does incremental cache
  // book-keeping.  For efficiency, prefer PushArc and SetArcs below
  // when possible.
  void AddArc(StateId s, const Arc &arc) {
    S *state = ExtendState(s);
    state->arcs.push_back(arc);
    if (arc.ilabel == 0) {
      ++state->niepsilons;
    }
    if (arc.olabel == 0) {
      ++state->noepsilons;
    }
    const Arc *parc = state->arcs.empty() ? 0 : &(state->arcs.back());
    SetProperties(AddArcProperties(Properties(), s, arc, parc));
    state->flags |= kCacheModified;
    if (cache_gc_ && s != cache_first_state_id_ &&
        !(state->flags & kCacheProtect)) {
      cache_size_ += sizeof(Arc);
      if (cache_size_ > cache_limit_)
        GC(s, false);
    }
  }

  // Adds a single arc to state s but delays cache book-keeping.
  // SetArcs must be called when all PushArc calls at a state are
  // complete.  Do not mix with calls to AddArc.
  void PushArc(StateId s, const Arc &arc) {
    S *state = ExtendState(s);
    state->arcs.push_back(arc);
  }

  // Marks arcs of state s as cached and does cache book-keeping after all
  // calls to PushArc have been completed.  Do not mix with calls to AddArc.
  void SetArcs(StateId s) {
    S *state = ExtendState(s);
    vector<Arc> &arcs = state->arcs;
    state->niepsilons = state->noepsilons = 0;
    for (size_t a = 0; a < arcs.size(); ++a) {
      const Arc &arc = arcs[a];
      if (arc.nextstate >= nknown_states_)
        nknown_states_ = arc.nextstate + 1;
      if (arc.ilabel == 0)
        ++state->niepsilons;
      if (arc.olabel == 0)
        ++state->noepsilons;
    }
    ExpandedState(s);
    state->flags |= kCacheArcs | kCacheRecent | kCacheModified;
    if (cache_gc_ && s != cache_first_state_id_ &&
        !(state->flags & kCacheProtect)) {
      cache_size_ += arcs.capacity() * sizeof(Arc);
      if (cache_size_ > cache_limit_)
        GC(s, false);
    }
  };

  void ReserveArcs(StateId s, size_t n) {
    S *state = ExtendState(s);
    state->arcs.reserve(n);
  }

  void DeleteArcs(StateId s, size_t n) {
    S *state = ExtendState(s);
    const vector<Arc> &arcs = state->arcs;
    for (size_t i = 0; i < n; ++i) {
      size_t j = arcs.size() - i - 1;
      if (arcs[j].ilabel == 0)
        --state->niepsilons;
      if (arcs[j].olabel == 0)
        --state->noepsilons;
    }

    state->arcs.resize(arcs.size() - n);
    SetProperties(DeleteArcsProperties(Properties()));
    state->flags |= kCacheModified;
    if (cache_gc_ && s != cache_first_state_id_ &&
        !(state->flags & kCacheProtect)) {
      cache_size_ -= n * sizeof(Arc);
    }
  }

  void DeleteArcs(StateId s) {
    S *state = ExtendState(s);
    size_t n = state->arcs.size();
    state->niepsilons = 0;
    state->noepsilons = 0;
    state->arcs.clear();
    SetProperties(DeleteArcsProperties(Properties()));
    state->flags |= kCacheModified;
    if (cache_gc_ && s != cache_first_state_id_ &&
        !(state->flags & kCacheProtect)) {
      cache_size_ -= n * sizeof(Arc);
    }
  }

  void DeleteStates(const vector<StateId> &dstates) {
    size_t old_num_states = NumStates();
    vector<StateId> newid(old_num_states, 0);
    for (size_t i = 0; i < dstates.size(); ++i)
      newid[dstates[i]] = kNoStateId;
    StateId nstates = 0;
    for (StateId s = 0; s < old_num_states; ++s) {
      if (newid[s] != kNoStateId) {
        newid[s] = nstates;
        ++nstates;
      }
    }
    // just for states_.resize(), does unnecessary walk.
    VectorFstBaseImpl<S>::DeleteStates(dstates);
    SetProperties(DeleteStatesProperties(Properties()));
    // Update list of cached states.
    typename list<StateId>::iterator siter = cache_states_.begin();
    while (siter != cache_states_.end()) {
      if (newid[*siter] != kNoStateId) {
        *siter = newid[*siter];
        ++siter;
      } else {
        cache_states_.erase(siter++);
      }
    }
  }

  void DeleteStates() {
    cache_states_.clear();
    allocator_->Free(cache_first_state_, cache_first_state_id_);
    for (int s = 0; s < NumStates(); ++s) {
      allocator_->Free(VectorFstBaseImpl<S>::GetState(s), s);
      SetState(s, 0);
    }
    nknown_states_ = 0;
    min_unexpanded_state_id_ = 0;
    cache_first_state_id_ = kNoStateId;
    cache_first_state_ = 0;
    cache_size_ = 0;
    cache_start_ = false;
    VectorFstBaseImpl<State>::DeleteStates();
    SetProperties(DeleteAllStatesProperties(Properties(),
                                            kExpanded | kMutable));
  }

  // Is the start state cached?
  bool HasStart() const {
    if (!cache_start_ && Properties(kError))
      cache_start_ = true;
    return cache_start_;
  }

  // Is the final weight of state s cached?
  bool HasFinal(StateId s) const {
    const S *state = CheckState(s);
    if (state && state->flags & kCacheFinal) {
      state->flags |= kCacheRecent;
      return true;
    } else {
      return false;
    }
  }

  // Are arcs of state s cached?
  bool HasArcs(StateId s) const {
    const S *state = CheckState(s);
    if (state && state->flags & kCacheArcs) {
      state->flags |= kCacheRecent;
      return true;
    } else {
      return false;
    }
  }

  Weight Final(StateId s) const {
    const S *state = GetState(s);
    return state->final;
  }

  size_t NumArcs(StateId s) const {
    const S *state = GetState(s);
    return state->arcs.size();
  }

  size_t NumInputEpsilons(StateId s) const {
    const S *state = GetState(s);
    return state->niepsilons;
  }

  size_t NumOutputEpsilons(StateId s) const {
    const S *state = GetState(s);
    return state->noepsilons;
  }

  // Provides information needed for generic arc iterator.
  void InitArcIterator(StateId s, ArcIteratorData<Arc> *data) const {
    const S *state = GetState(s);
    data->base = 0;
    data->narcs = state->arcs.size();
    data->arcs = data->narcs > 0 ? &(state->arcs[0]) : 0;
    data->ref_count = &(state->ref_count);
    ++(*data->ref_count);
  }

  // Number of known states.
  StateId NumKnownStates() const { return nknown_states_; }

  // Update number of known states taking in account the existence of state s.
  void UpdateNumKnownStates(StateId s) {
    if (s >= nknown_states_)
      nknown_states_ = s + 1;
  }

  // Find the mininum never-expanded state Id
  StateId MinUnexpandedState() const {
    while (min_unexpanded_state_id_ < expanded_states_.size() &&
          expanded_states_[min_unexpanded_state_id_])
      ++min_unexpanded_state_id_;
    return min_unexpanded_state_id_;
  }

  // Removes from cache_states_ and uncaches (not referenced-counted
  // or protected) states that have not been accessed since the last
  // GC until at most cache_fraction * cache_limit_ bytes are cached.
  // If that fails to free enough, recurs uncaching recently visited
  // states as well. If still unable to free enough memory, then
  // widens cache_limit_ to fulfill condition.
  void GC(StateId current, bool free_recent,  float cache_fraction = 0.666);

  // Setc/clears GC protection: if true, new states are protected
  // from garbage collection.
  void GCProtect(bool on) { protect_ = on; }

  void ExpandedState(StateId s) {
    if (s < min_unexpanded_state_id_)
      return;
    while (expanded_states_.size() <= s)
      expanded_states_.push_back(false);
    expanded_states_[s] = true;
  }

  C *GetAllocator() const {
    return allocator_;
  }

  // Caching on/off switch, limit and size accessors.
  bool GetCacheGc() const { return cache_gc_; }
  size_t GetCacheLimit() const { return cache_limit_; }
  size_t GetCacheSize() const { return cache_size_; }

 private:
  static const size_t kMinCacheLimit = 8096;   // Minimum (non-zero) cache limit

  static const uint32 kCacheFinal =    0x0001;  // Final weight has been cached
  static const uint32 kCacheArcs =     0x0002;  // Arcs have been cached
  static const uint32 kCacheRecent =   0x0004;  // Mark as visited since GC
  static const uint32 kCacheProtect =  0x0008;  // Mark state as GC protected

 public:
  static const uint32 kCacheModified = 0x0010;  // Mark state as modified
  static const uint32 kCacheFlags = kCacheFinal | kCacheArcs | kCacheRecent
      | kCacheProtect | kCacheModified;

 private:
  C *allocator_;                             // used to allocate new states
  mutable bool cache_start_;                 // Is the start state cached?
  StateId nknown_states_;                    // # of known states
  vector<bool> expanded_states_;             // states that have been expanded
  mutable StateId min_unexpanded_state_id_;  // minimum never-expanded state Id
  StateId cache_first_state_id_;             // First cached state id
  S *cache_first_state_;                     // First cached state
  list<StateId> cache_states_;               // list of currently cached states
  bool cache_gc_;                            // enable GC
  size_t cache_size_;                        // # of bytes cached
  size_t cache_limit_;                       // # of bytes allowed before GC
  bool protect_;                             // Protect new states from GC

  void operator=(const CacheBaseImpl<S, C> &impl);    // disallow
};

// Gets a state from its ID; add it if necessary.
template <class S, class C>
S *CacheBaseImpl<S, C>::ExtendState(typename S::Arc::StateId s) {
  // If 'protect_' true and a new state, protects from garbage collection.
  if (s == cache_first_state_id_) {
    return cache_first_state_;                   // Return 1st cached state
  } else if (cache_limit_ == 0 && cache_first_state_id_ == kNoStateId) {
    cache_first_state_id_ = s;                   // Remember 1st cached state
    cache_first_state_ = allocator_->Allocate(s);
    if (protect_) cache_first_state_->flags |= kCacheProtect;
    return cache_first_state_;
  } else if (cache_first_state_id_ != kNoStateId &&
             cache_first_state_->ref_count == 0 &&
             !(cache_first_state_->flags & kCacheProtect)) {
    // With Default allocator, the Free and Allocate will reuse the same S*.
    allocator_->Free(cache_first_state_, cache_first_state_id_);
    cache_first_state_id_ = s;
    cache_first_state_ = allocator_->Allocate(s);
    if (protect_) cache_first_state_->flags |= kCacheProtect;
    return cache_first_state_;                   // Return 1st cached state
  } else {
    while (NumStates() <= s)                     // Add state to main cache
      AddState(0);
    S *state = VectorFstBaseImpl<S>::GetState(s);
    if (!state) {
      state = allocator_->Allocate(s);
      if (protect_) state->flags |= kCacheProtect;
      SetState(s, state);
      if (cache_first_state_id_ != kNoStateId) {  // Forget 1st cached state
        while (NumStates() <= cache_first_state_id_)
          AddState(0);
        SetState(cache_first_state_id_, cache_first_state_);
        if (cache_gc_ && !(cache_first_state_->flags & kCacheProtect)) {
          cache_states_.push_back(cache_first_state_id_);
          cache_size_ += sizeof(S) +
                         cache_first_state_->arcs.capacity() * sizeof(Arc);
        }
        cache_limit_ = kMinCacheLimit;
        cache_first_state_id_ = kNoStateId;
        cache_first_state_ = 0;
      }
      if (cache_gc_ && !protect_) {
        cache_states_.push_back(s);
        cache_size_ += sizeof(S);
        if (cache_size_ > cache_limit_)
          GC(s, false);
      }
    }
    return state;
  }
}

// Removes from cache_states_ and uncaches (not referenced-counted or
// protected) states that have not been accessed since the last GC
// until at most cache_fraction * cache_limit_ bytes are cached.  If
// that fails to free enough, recurs uncaching recently visited states
// as well. If still unable to free enough memory, then widens cache_limit_
// to fulfill condition.
template <class S, class C>
void CacheBaseImpl<S, C>::GC(typename S::Arc::StateId current,
                             bool free_recent, float cache_fraction) {
  if (!cache_gc_)
    return;
  VLOG(2) << "CacheImpl: Enter GC: object = " << Type() << "(" << this
          << "), free recently cached = " << free_recent
          << ", cache size = " << cache_size_
          << ", cache frac = " << cache_fraction
          << ", cache limit = " << cache_limit_ << "\n";
  typename list<StateId>::iterator siter = cache_states_.begin();

  size_t cache_target = cache_fraction * cache_limit_;
  while (siter != cache_states_.end()) {
    StateId s = *siter;
    S* state = VectorFstBaseImpl<S>::GetState(s);
    if (cache_size_ > cache_target && state->ref_count == 0 &&
        (free_recent || !(state->flags & kCacheRecent)) && s != current) {
      cache_size_ -= sizeof(S) + state->arcs.capacity() * sizeof(Arc);
      allocator_->Free(state, s);
      SetState(s, 0);
      cache_states_.erase(siter++);
    } else {
      state->flags &= ~kCacheRecent;
      ++siter;
    }
  }
  if (!free_recent && cache_size_ > cache_target) {   // recurses on recent
    GC(current, true);
  } else if (cache_target > 0) {                      // widens cache limit
    while (cache_size_ > cache_target) {
      cache_limit_ *= 2;
      cache_target *= 2;
    }
  } else if (cache_size_ > 0) {
    FSTERROR() << "CacheImpl:GC: Unable to free all cached states";
  }
  VLOG(2) << "CacheImpl: Exit GC: object = " << Type() << "(" << this
          << "), free recently cached = " << free_recent
          << ", cache size = " << cache_size_
          << ", cache frac = " << cache_fraction
          << ", cache limit = " << cache_limit_ << "\n";
}

template <class S, class C> const uint32 CacheBaseImpl<S, C>::kCacheFinal;
template <class S, class C> const uint32 CacheBaseImpl<S, C>::kCacheArcs;
template <class S, class C> const uint32 CacheBaseImpl<S, C>::kCacheRecent;
template <class S, class C> const uint32 CacheBaseImpl<S, C>::kCacheModified;
template <class S, class C> const size_t CacheBaseImpl<S, C>::kMinCacheLimit;

// Arcs implemented by an STL vector per state. Similar to VectorState
// but adds flags and ref count to keep track of what has been cached.
template <class A>
struct CacheState {
  typedef A Arc;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;

  CacheState() :  final(Weight::Zero()), flags(0), ref_count(0) {}

  void Reset() {
    flags = 0;
    ref_count = 0;
    arcs.resize(0);
  }

  Weight final;              // Final weight
  vector<A> arcs;            // Arcs represenation
  size_t niepsilons;         // # of input epsilons
  size_t noepsilons;         // # of output epsilons
  mutable uint32 flags;
  mutable int ref_count;
};

// A CacheBaseImpl with a commonly used CacheState.
template <class A>
class CacheImpl : public CacheBaseImpl< CacheState<A> > {
 public:
  typedef CacheState<A> State;

  CacheImpl() {}

  explicit CacheImpl(const CacheOptions &opts)
      : CacheBaseImpl< CacheState<A> >(opts) {}

  CacheImpl(const CacheImpl<A> &impl, bool preserve_cache = false)
      : CacheBaseImpl<State>(impl, preserve_cache) {}

 private:
  void operator=(const CacheImpl<State> &impl);    // disallow
};


// Use this to make a state iterator for a CacheBaseImpl-derived Fst,
// which must have type 'State' defined.  Note this iterator only
// returns those states reachable from the initial state, so consider
// implementing a class-specific one.
template <class F>
class CacheStateIterator : public StateIteratorBase<typename F::Arc> {
 public:
  typedef typename F::Arc Arc;
  typedef typename Arc::StateId StateId;
  typedef typename F::State State;
  typedef CacheBaseImpl<State> Impl;

  CacheStateIterator(const F &fst, Impl *impl)
      : fst_(fst), impl_(impl), s_(0) {
        fst_.Start();  // force start state
      }

  bool Done() const {
    if (s_ < impl_->NumKnownStates())
      return false;
    if (s_ < impl_->NumKnownStates())
      return false;
    for (StateId u = impl_->MinUnexpandedState();
         u < impl_->NumKnownStates();
         u = impl_->MinUnexpandedState()) {
      // force state expansion
      ArcIterator<F> aiter(fst_, u);
      aiter.SetFlags(kArcValueFlags, kArcValueFlags | kArcNoCache);
      for (; !aiter.Done(); aiter.Next())
        impl_->UpdateNumKnownStates(aiter.Value().nextstate);
      impl_->ExpandedState(u);
      if (s_ < impl_->NumKnownStates())
        return false;
    }
    return true;
  }

  StateId Value() const { return s_; }

  void Next() { ++s_; }

  void Reset() { s_ = 0; }

 private:
  // This allows base class virtual access to non-virtual derived-
  // class members of the same name. It makes the derived class more
  // efficient to use but unsafe to further derive.
  virtual bool Done_() const { return Done(); }
  virtual StateId Value_() const { return Value(); }
  virtual void Next_() { Next(); }
  virtual void Reset_() { Reset(); }

  const F &fst_;
  Impl *impl_;
  StateId s_;
};


// Use this to make an arc iterator for a CacheBaseImpl-derived Fst,
// which must have types 'Arc' and 'State' defined.
template <class F,
          class C = DefaultCacheStateAllocator<CacheState<typename F::Arc> > >
class CacheArcIterator {
 public:
  typedef typename F::Arc Arc;
  typedef typename F::State State;
  typedef typename Arc::StateId StateId;
  typedef CacheBaseImpl<State, C> Impl;

  CacheArcIterator(Impl *impl, StateId s) : i_(0) {
    state_ = impl->ExtendState(s);
    ++state_->ref_count;
  }

  ~CacheArcIterator() { --state_->ref_count;  }

  bool Done() const { return i_ >= state_->arcs.size(); }

  const Arc& Value() const { return state_->arcs[i_]; }

  void Next() { ++i_; }

  size_t Position() const { return i_; }

  void Reset() { i_ = 0; }

  void Seek(size_t a) { i_ = a; }

  uint32 Flags() const {
    return kArcValueFlags;
  }

  void SetFlags(uint32 flags, uint32 mask) {}

 private:
  const State *state_;
  size_t i_;

  DISALLOW_COPY_AND_ASSIGN(CacheArcIterator);
};

// Use this to make a mutable arc iterator for a CacheBaseImpl-derived Fst,
// which must have types 'Arc' and 'State' defined.
template <class F,
          class C = DefaultCacheStateAllocator<CacheState<typename F::Arc> > >
class CacheMutableArcIterator
    : public MutableArcIteratorBase<typename F::Arc> {
 public:
  typedef typename F::State State;
  typedef typename F::Arc Arc;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef CacheBaseImpl<State, C> Impl;

  // You will need to call MutateCheck() in the constructor.
  CacheMutableArcIterator(Impl *impl, StateId s) : i_(0), s_(s), impl_(impl) {
    state_ = impl_->ExtendState(s_);
    ++state_->ref_count;
  };

  ~CacheMutableArcIterator() {
    --state_->ref_count;
  }

  bool Done() const { return i_ >= state_->arcs.size(); }

  const Arc& Value() const { return state_->arcs[i_]; }

  void Next() { ++i_; }

  size_t Position() const { return i_; }

  void Reset() { i_ = 0; }

  void Seek(size_t a) { i_ = a; }

  void SetValue(const Arc& arc) {
    state_->flags |= CacheBaseImpl<State, C>::kCacheModified;
    uint64 properties = impl_->Properties();
    Arc& oarc = state_->arcs[i_];
    if (oarc.ilabel != oarc.olabel)
      properties &= ~kNotAcceptor;
    if (oarc.ilabel == 0) {
      --state_->niepsilons;
      properties &= ~kIEpsilons;
      if (oarc.olabel == 0)
        properties &= ~kEpsilons;
    }
    if (oarc.olabel == 0) {
      --state_->noepsilons;
      properties &= ~kOEpsilons;
    }
    if (oarc.weight != Weight::Zero() && oarc.weight != Weight::One())
      properties &= ~kWeighted;
    oarc = arc;
    if (arc.ilabel != arc.olabel) {
      properties |= kNotAcceptor;
      properties &= ~kAcceptor;
    }
    if (arc.ilabel == 0) {
      ++state_->niepsilons;
      properties |= kIEpsilons;
      properties &= ~kNoIEpsilons;
      if (arc.olabel == 0) {
        properties |= kEpsilons;
        properties &= ~kNoEpsilons;
      }
    }
    if (arc.olabel == 0) {
      ++state_->noepsilons;
      properties |= kOEpsilons;
      properties &= ~kNoOEpsilons;
    }
    if (arc.weight != Weight::Zero() && arc.weight != Weight::One()) {
      properties |= kWeighted;
      properties &= ~kUnweighted;
    }
    properties &= kSetArcProperties | kAcceptor | kNotAcceptor |
        kEpsilons | kNoEpsilons | kIEpsilons | kNoIEpsilons |
        kOEpsilons | kNoOEpsilons | kWeighted | kUnweighted;
    impl_->SetProperties(properties);
  }

  uint32 Flags() const {
    return kArcValueFlags;
  }

  void SetFlags(uint32 f, uint32 m) {}

 private:
  virtual bool Done_() const { return Done(); }
  virtual const Arc& Value_() const { return Value(); }
  virtual void Next_() { Next(); }
  virtual size_t Position_() const { return Position(); }
  virtual void Reset_() { Reset(); }
  virtual void Seek_(size_t a) { Seek(a); }
  virtual void SetValue_(const Arc &a) { SetValue(a); }
  uint32 Flags_() const { return Flags(); }
  void SetFlags_(uint32 f, uint32 m) { SetFlags(f, m); }

  size_t i_;
  StateId s_;
  Impl *impl_;
  State *state_;

  DISALLOW_COPY_AND_ASSIGN(CacheMutableArcIterator);
};

}  // namespace fst

#endif  // FST_LIB_CACHE_H__
