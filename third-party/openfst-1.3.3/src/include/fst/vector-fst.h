// vector-fst.h

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
// Simple concrete, mutable FST whose states and arcs are stored in STL
// vectors.

#ifndef FST_LIB_VECTOR_FST_H__
#define FST_LIB_VECTOR_FST_H__

#include <string>
#include <vector>
using std::vector;

#include <fst/mutable-fst.h>
#include <fst/test-properties.h>


namespace fst {

template <class A> class VectorFst;
template <class F, class G> void Cast(const F &, G *);


// States and arcs implemented by STL vectors, templated on the
// State definition. This does not manage the Fst properties.
template <class State>
class VectorFstBaseImpl : public FstImpl<typename State::Arc> {
 public:
  typedef typename State::Arc Arc;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::StateId StateId;

  VectorFstBaseImpl() : start_(kNoStateId) {}

  ~VectorFstBaseImpl() {
    for (StateId s = 0; s < states_.size(); ++s)
      delete states_[s];
  }

  StateId Start() const { return start_; }

  Weight Final(StateId s) const { return states_[s]->final; }

  StateId NumStates() const { return states_.size(); }

  size_t NumArcs(StateId s) const { return states_[s]->arcs.size(); }

  void SetStart(StateId s) { start_ = s; }

  void SetFinal(StateId s, Weight w) { states_[s]->final = w; }

  StateId AddState() {
    states_.push_back(new State);
    return states_.size() - 1;
  }

  StateId AddState(State *state) {
    states_.push_back(state);
    return states_.size() - 1;
  }

  void AddArc(StateId s, const Arc &arc) {
    states_[s]->arcs.push_back(arc);
  }

  void DeleteStates(const vector<StateId>& dstates) {
    vector<StateId> newid(states_.size(), 0);
    for (size_t i = 0; i < dstates.size(); ++i)
      newid[dstates[i]] = kNoStateId;
    StateId nstates = 0;
    for (StateId s = 0; s < states_.size(); ++s) {
      if (newid[s] != kNoStateId) {
        newid[s] = nstates;
        if (s != nstates)
          states_[nstates] = states_[s];
        ++nstates;
      } else {
        delete states_[s];
      }
    }
    states_.resize(nstates);
    for (StateId s = 0; s < states_.size(); ++s) {
      vector<Arc> &arcs = states_[s]->arcs;
      size_t narcs = 0;
      for (size_t i = 0; i < arcs.size(); ++i) {
        StateId t = newid[arcs[i].nextstate];
        if (t != kNoStateId) {
          arcs[i].nextstate = t;
          if (i != narcs)
            arcs[narcs] = arcs[i];
          ++narcs;
        } else {
          if (arcs[i].ilabel == 0)
            --states_[s]->niepsilons;
          if (arcs[i].olabel == 0)
            --states_[s]->noepsilons;
        }
      }
      arcs.resize(narcs);
    }
    if (Start() != kNoStateId)
      SetStart(newid[Start()]);
  }

  void DeleteStates() {
    for (StateId s = 0; s < states_.size(); ++s)
      delete states_[s];
    states_.clear();
    SetStart(kNoStateId);
  }

  void DeleteArcs(StateId s, size_t n) {
    states_[s]->arcs.resize(states_[s]->arcs.size() - n);
  }

  void DeleteArcs(StateId s) { states_[s]->arcs.clear(); }

  State *GetState(StateId s) { return states_[s]; }

  const State *GetState(StateId s) const { return states_[s]; }

  void SetState(StateId s, State *state) { states_[s] = state; }

  void ReserveStates(StateId n) { states_.reserve(n); }

  void ReserveArcs(StateId s, size_t n) { states_[s]->arcs.reserve(n); }

  // Provide information needed for generic state iterator
  void InitStateIterator(StateIteratorData<Arc> *data) const {
    data->base = 0;
    data->nstates = states_.size();
  }

  // Provide information needed for generic arc iterator
  void InitArcIterator(StateId s, ArcIteratorData<Arc> *data) const {
    data->base = 0;
    data->narcs = states_[s]->arcs.size();
    data->arcs = data->narcs > 0 ? &states_[s]->arcs[0] : 0;
    data->ref_count = 0;
  }

 private:
  vector<State *> states_;      // States represenation.
  StateId start_;               // initial state

  DISALLOW_COPY_AND_ASSIGN(VectorFstBaseImpl);
};

// Arcs implemented by an STL vector per state.
template <class A>
struct VectorState {
  typedef A Arc;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;

  VectorState() : final(Weight::Zero()), niepsilons(0), noepsilons(0) {}

  Weight final;              // Final weight
  vector<A> arcs;            // Arcs represenation
  size_t niepsilons;         // # of input epsilons
  size_t noepsilons;         // # of output epsilons
};

// This is a VectorFstBaseImpl container that holds VectorState's.  It
// manages Fst properties and the # of input and output epsilons.
template <class A>
class VectorFstImpl : public VectorFstBaseImpl< VectorState<A> > {
 public:
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::Properties;

  using VectorFstBaseImpl<VectorState<A> >::Start;
  using VectorFstBaseImpl<VectorState<A> >::NumStates;
  using VectorFstBaseImpl<VectorState<A> >::GetState;
  using VectorFstBaseImpl<VectorState<A> >::ReserveArcs;

  friend class MutableArcIterator< VectorFst<A> >;

  typedef VectorFstBaseImpl< VectorState<A> > BaseImpl;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;

  VectorFstImpl() {
    SetType("vector");
    SetProperties(kNullProperties | kStaticProperties);
  }
  explicit VectorFstImpl(const Fst<A> &fst);

  static VectorFstImpl<A> *Read(istream &strm, const FstReadOptions &opts);

  size_t NumInputEpsilons(StateId s) const { return GetState(s)->niepsilons; }

  size_t NumOutputEpsilons(StateId s) const { return GetState(s)->noepsilons; }

  void SetStart(StateId s) {
    BaseImpl::SetStart(s);
    SetProperties(SetStartProperties(Properties()));
  }

  void SetFinal(StateId s, Weight w) {
    Weight ow = BaseImpl::Final(s);
    BaseImpl::SetFinal(s, w);
    SetProperties(SetFinalProperties(Properties(), ow, w));
  }

  StateId AddState() {
    StateId s = BaseImpl::AddState();
    SetProperties(AddStateProperties(Properties()));
    return s;
  }

  void AddArc(StateId s, const A &arc) {
    VectorState<A> *state = GetState(s);
    if (arc.ilabel == 0) {
      ++state->niepsilons;
    }
    if (arc.olabel == 0) {
      ++state->noepsilons;
    }

    const A *parc = state->arcs.empty() ? 0 : &(state->arcs.back());
    SetProperties(AddArcProperties(Properties(), s, arc, parc));

    BaseImpl::AddArc(s, arc);
  }

  void DeleteStates(const vector<StateId> &dstates) {
    BaseImpl::DeleteStates(dstates);
    SetProperties(DeleteStatesProperties(Properties()));
  }

  void DeleteStates() {
    BaseImpl::DeleteStates();
    SetProperties(DeleteAllStatesProperties(Properties(),
                                            kStaticProperties));
  }

  void DeleteArcs(StateId s, size_t n) {
    const vector<A> &arcs = GetState(s)->arcs;
    for (size_t i = 0; i < n; ++i) {
      size_t j = arcs.size() - i - 1;
      if (arcs[j].ilabel == 0)
        --GetState(s)->niepsilons;
      if (arcs[j].olabel == 0)
        --GetState(s)->noepsilons;
    }
    BaseImpl::DeleteArcs(s, n);
    SetProperties(DeleteArcsProperties(Properties()));
  }

  void DeleteArcs(StateId s) {
    GetState(s)->niepsilons = 0;
    GetState(s)->noepsilons = 0;
    BaseImpl::DeleteArcs(s);
    SetProperties(DeleteArcsProperties(Properties()));
  }

  // Properties always true of this Fst class
  static const uint64 kStaticProperties = kExpanded | kMutable;

 private:
  // Current file format version
  static const int kFileVersion = 2;
  // Minimum file format version supported
  static const int kMinFileVersion = 1;

  DISALLOW_COPY_AND_ASSIGN(VectorFstImpl);
};

template <class A> const uint64 VectorFstImpl<A>::kStaticProperties;
template <class A> const int VectorFstImpl<A>::kFileVersion;
template <class A> const int VectorFstImpl<A>::kMinFileVersion;


template <class A>
VectorFstImpl<A>::VectorFstImpl(const Fst<A> &fst) {
  SetType("vector");
  SetInputSymbols(fst.InputSymbols());
  SetOutputSymbols(fst.OutputSymbols());
  BaseImpl::SetStart(fst.Start());
  if (fst.Properties(kExpanded, false))
    BaseImpl::ReserveStates(CountStates(fst));

  for (StateIterator< Fst<A> > siter(fst);
       !siter.Done();
       siter.Next()) {
    StateId s = siter.Value();
    BaseImpl::AddState();
    BaseImpl::SetFinal(s, fst.Final(s));
    ReserveArcs(s, fst.NumArcs(s));
    for (ArcIterator< Fst<A> > aiter(fst, s);
         !aiter.Done();
         aiter.Next()) {
      const A &arc = aiter.Value();
      BaseImpl::AddArc(s, arc);
      if (arc.ilabel == 0)
        ++GetState(s)->niepsilons;
      if (arc.olabel == 0)
        ++GetState(s)->noepsilons;
    }
  }
  SetProperties(fst.Properties(kCopyProperties, false) | kStaticProperties);
}

template <class A>
VectorFstImpl<A> *VectorFstImpl<A>::Read(istream &strm,
                                         const FstReadOptions &opts) {
  VectorFstImpl<A> *impl = new VectorFstImpl;
  FstHeader hdr;
  if (!impl->ReadHeader(strm, opts, kMinFileVersion, &hdr)) {
    delete impl;
    return 0;
  }
  impl->BaseImpl::SetStart(hdr.Start());
  if (hdr.NumStates() != kNoStateId) {
    impl->ReserveStates(hdr.NumStates());
  }

  StateId s = 0;
  for (;hdr.NumStates() == kNoStateId || s < hdr.NumStates(); ++s) {
    typename A::Weight final;
    if (!final.Read(strm)) break;
    impl->BaseImpl::AddState();
    VectorState<A> *state = impl->GetState(s);
    state->final = final;
    int64 narcs;
    ReadType(strm, &narcs);
    if (!strm) {
      LOG(ERROR) << "VectorFst::Read: read failed: " << opts.source;
      delete impl;
      return 0;
    }
    impl->ReserveArcs(s, narcs);
    for (size_t j = 0; j < narcs; ++j) {
      A arc;
      ReadType(strm, &arc.ilabel);
      ReadType(strm, &arc.olabel);
      arc.weight.Read(strm);
       ReadType(strm, &arc.nextstate);
       if (!strm) {
        LOG(ERROR) << "VectorFst::Read: read failed: " << opts.source;
        delete impl;
        return 0;
      }
      impl->BaseImpl::AddArc(s, arc);
      if (arc.ilabel == 0)
        ++state->niepsilons;
      if (arc.olabel == 0)
        ++state->noepsilons;
    }
  }
  if (hdr.NumStates() != kNoStateId && s != hdr.NumStates()) {
    LOG(ERROR) << "VectorFst::Read: unexpected end of file: " << opts.source;
    delete impl;
    return 0;
  }
  return impl;
}

// Converts a string into a weight.
template <class W> class WeightFromString {
 public:
  W operator()(const string &s);
};

// Generic case fails.
template <class W> inline
W WeightFromString<W>::operator()(const string &s) {
  FSTERROR() << "VectorFst::Read: Obsolete file format";
  return W::NoWeight();
}

// TropicalWeight version.
template <> inline
TropicalWeight WeightFromString<TropicalWeight>::operator()(const string &s) {
  float f;
  memcpy(&f, s.data(), sizeof(f));
  return TropicalWeight(f);
}

// LogWeight version.
template <> inline
LogWeight WeightFromString<LogWeight>::operator()(const string &s) {
  float f;
  memcpy(&f, s.data(), sizeof(f));
  return LogWeight(f);
}

// Simple concrete, mutable FST. This class attaches interface to
// implementation and handles reference counting, delegating most
// methods to ImplToMutableFst. Supports additional operations:
// ReserveStates and ReserveArcs (cf. STL vectors).
template <class A>
class VectorFst : public ImplToMutableFst< VectorFstImpl<A> > {
 public:
  friend class StateIterator< VectorFst<A> >;
  friend class ArcIterator< VectorFst<A> >;
  friend class MutableArcIterator< VectorFst<A> >;
  template <class F, class G> friend void Cast(const F &, G *);

  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef VectorFstImpl<A> Impl;

  VectorFst() : ImplToMutableFst<Impl>(new Impl) {}

  explicit VectorFst(const Fst<A> &fst)
      : ImplToMutableFst<Impl>(new Impl(fst)) {}

  VectorFst(const VectorFst<A> &fst) : ImplToMutableFst<Impl>(fst) {}

  // Get a copy of this VectorFst. See Fst<>::Copy() for further doc.
  virtual VectorFst<A> *Copy(bool safe = false) const {
    return new VectorFst<A>(*this);
  }

  VectorFst<A> &operator=(const VectorFst<A> &fst) {
    SetImpl(fst.GetImpl(), false);
    return *this;
  }

  virtual VectorFst<A> &operator=(const Fst<A> &fst) {
    if (this != &fst) SetImpl(new Impl(fst));
    return *this;
  }

  // Read a VectorFst from an input stream; return NULL on error
  static VectorFst<A> *Read(istream &strm, const FstReadOptions &opts) {
    Impl* impl = Impl::Read(strm, opts);
    return impl ? new VectorFst<A>(impl) : 0;
  }

  // Read a VectorFst from a file; return NULL on error
  // Empty filename reads from standard input
  static VectorFst<A> *Read(const string &filename) {
    Impl* impl = ImplToExpandedFst<Impl, MutableFst<A> >::Read(filename);
    return impl ? new VectorFst<A>(impl) : 0;
  }

  virtual bool Write(ostream &strm, const FstWriteOptions &opts) const {
    return WriteFst(*this, strm, opts);
  }

  virtual bool Write(const string &filename) const {
    return Fst<A>::WriteFile(filename);
  }

  template <class F>
  static bool WriteFst(const F &fst, ostream &strm,
                       const FstWriteOptions &opts);

  void ReserveStates(StateId n) {
    MutateCheck();
    GetImpl()->ReserveStates(n);
  }

  void ReserveArcs(StateId s, size_t n) {
    MutateCheck();
    GetImpl()->ReserveArcs(s, n);
  }

  virtual void InitStateIterator(StateIteratorData<Arc> *data) const {
    GetImpl()->InitStateIterator(data);
  }

  virtual void InitArcIterator(StateId s, ArcIteratorData<Arc> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

  virtual inline
  void InitMutableArcIterator(StateId s, MutableArcIteratorData<A> *);

 private:
  explicit VectorFst(Impl *impl) : ImplToMutableFst<Impl>(impl) {}

  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst< Impl, MutableFst<A> >::GetImpl(); }

  void SetImpl(Impl *impl, bool own_impl = true) {
    ImplToFst< Impl, MutableFst<A> >::SetImpl(impl, own_impl);
  }

  void MutateCheck() { return ImplToMutableFst<Impl>::MutateCheck(); }
};

// Specialization for VectorFst; see generic version in fst.h
// for sample usage (but use the VectorFst type!). This version
// should inline.
template <class A>
class StateIterator< VectorFst<A> > {
 public:
  typedef typename A::StateId StateId;

  explicit StateIterator(const VectorFst<A> &fst)
      : nstates_(fst.GetImpl()->NumStates()), s_(0) {}

  bool Done() const { return s_ >= nstates_; }

  StateId Value() const { return s_; }

  void Next() { ++s_; }

  void Reset() { s_ = 0; }

 private:
  StateId nstates_;
  StateId s_;

  DISALLOW_COPY_AND_ASSIGN(StateIterator);
};

// Writes Fst to file, will call CountStates so may involve two passes if
// called from an Fst that is not derived from Expanded.
template <class A>
template <class F>
bool VectorFst<A>::WriteFst(const F &fst, ostream &strm,
                            const FstWriteOptions &opts) {
  static const int kFileVersion = 2;
  bool update_header = true;
  FstHeader hdr;
  hdr.SetStart(fst.Start());
  hdr.SetNumStates(kNoStateId);
  size_t start_offset = 0;
  if (fst.Properties(kExpanded, false) || (start_offset = strm.tellp()) != -1) {
    hdr.SetNumStates(CountStates(fst));
    update_header = false;
  }
  uint64 properties = fst.Properties(kCopyProperties, false) |
      VectorFstImpl<A>::kStaticProperties;
  FstImpl<A>::WriteFstHeader(fst, strm, opts, kFileVersion, "vector",
                             properties, &hdr);
  StateId num_states = 0;
  for (StateIterator<F> siter(fst); !siter.Done(); siter.Next()) {
    typename A::StateId s = siter.Value();
    fst.Final(s).Write(strm);
    int64 narcs = fst.NumArcs(s);
    WriteType(strm, narcs);
    for (ArcIterator<F> aiter(fst, s); !aiter.Done(); aiter.Next()) {
      const A &arc = aiter.Value();
      WriteType(strm, arc.ilabel);
      WriteType(strm, arc.olabel);
      arc.weight.Write(strm);
      WriteType(strm, arc.nextstate);
    }
    num_states++;
  }
  strm.flush();
  if (!strm) {
    LOG(ERROR) << "VectorFst::Write: write failed: " << opts.source;
    return false;
  }
  if (update_header) {
    hdr.SetNumStates(num_states);
    return FstImpl<A>::UpdateFstHeader(fst, strm, opts, kFileVersion, "vector",
                                       properties, &hdr, start_offset);
  } else {
    if (num_states != hdr.NumStates()) {
      LOG(ERROR) << "Inconsistent number of states observed during write";
      return false;
    }
  }
  return true;
}

// Specialization for VectorFst; see generic version in fst.h
// for sample usage (but use the VectorFst type!). This version
// should inline.
template <class A>
class ArcIterator< VectorFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const VectorFst<A> &fst, StateId s)
      : arcs_(fst.GetImpl()->GetState(s)->arcs), i_(0) {}

  bool Done() const { return i_ >= arcs_.size(); }

  const A& Value() const { return arcs_[i_]; }

  void Next() { ++i_; }

  void Reset() { i_ = 0; }

  void Seek(size_t a) { i_ = a; }

  size_t Position() const { return i_; }

  uint32 Flags() const {
    return kArcValueFlags;
  }

  void SetFlags(uint32 f, uint32 m) {}

 private:
  const vector<A>& arcs_;
  size_t i_;

  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};

// Specialization for VectorFst; see generic version in fst.h
// for sample usage (but use the VectorFst type!). This version
// should inline.
template <class A>
class MutableArcIterator< VectorFst<A> >
  : public MutableArcIteratorBase<A> {
 public:
  typedef typename A::StateId StateId;
  typedef typename A::Weight Weight;

  MutableArcIterator(VectorFst<A> *fst, StateId s) : i_(0) {
    fst->MutateCheck();
    state_ = fst->GetImpl()->GetState(s);
    properties_ = &fst->GetImpl()->properties_;
  }

  bool Done() const { return i_ >= state_->arcs.size(); }

  const A& Value() const { return state_->arcs[i_]; }

  void Next() { ++i_; }

  size_t Position() const { return i_; }

  void Reset() { i_ = 0; }

  void Seek(size_t a) { i_ = a; }

  void SetValue(const A &arc) {
    A& oarc = state_->arcs[i_];
    if (oarc.ilabel != oarc.olabel)
      *properties_ &= ~kNotAcceptor;
    if (oarc.ilabel == 0) {
      --state_->niepsilons;
      *properties_ &= ~kIEpsilons;
      if (oarc.olabel == 0)
        *properties_ &= ~kEpsilons;
    }
    if (oarc.olabel == 0) {
      --state_->noepsilons;
      *properties_ &= ~kOEpsilons;
    }
    if (oarc.weight != Weight::Zero() && oarc.weight != Weight::One())
      *properties_ &= ~kWeighted;
    oarc = arc;
    if (arc.ilabel != arc.olabel) {
      *properties_ |= kNotAcceptor;
      *properties_ &= ~kAcceptor;
    }
    if (arc.ilabel == 0) {
      ++state_->niepsilons;
      *properties_ |= kIEpsilons;
      *properties_ &= ~kNoIEpsilons;
      if (arc.olabel == 0) {
        *properties_ |= kEpsilons;
        *properties_ &= ~kNoEpsilons;
      }
    }
    if (arc.olabel == 0) {
      ++state_->noepsilons;
      *properties_ |= kOEpsilons;
      *properties_ &= ~kNoOEpsilons;
    }
    if (arc.weight != Weight::Zero() && arc.weight != Weight::One()) {
      *properties_ |= kWeighted;
      *properties_ &= ~kUnweighted;
    }
    *properties_ &= kSetArcProperties | kAcceptor | kNotAcceptor |
        kEpsilons | kNoEpsilons | kIEpsilons | kNoIEpsilons |
        kOEpsilons | kNoOEpsilons | kWeighted | kUnweighted;
  }

  uint32 Flags() const {
    return kArcValueFlags;
  }

  void SetFlags(uint32 f, uint32 m) {}


 private:
  // This allows base-class virtual access to non-virtual derived-
  // class members of the same name. It makes the derived class more
  // efficient to use but unsafe to further derive.
  virtual bool Done_() const { return Done(); }
  virtual const A& Value_() const { return Value(); }
  virtual void Next_() { Next(); }
  virtual size_t Position_() const { return Position(); }
  virtual void Reset_() { Reset(); }
  virtual void Seek_(size_t a) { Seek(a); }
  virtual void SetValue_(const A &a) { SetValue(a); }
  uint32 Flags_() const { return Flags(); }
  void SetFlags_(uint32 f, uint32 m) { SetFlags(f, m); }

  struct VectorState<A> *state_;
  uint64 *properties_;
  size_t i_;

  DISALLOW_COPY_AND_ASSIGN(MutableArcIterator);
};

// Provide information needed for the generic mutable arc iterator
template <class A> inline
void VectorFst<A>::InitMutableArcIterator(
    StateId s, MutableArcIteratorData<A> *data) {
  data->base = new MutableArcIterator< VectorFst<A> >(this, s);
}

// A useful alias when using StdArc.
typedef VectorFst<StdArc> StdVectorFst;

}  // namespace fst

#endif  // FST_LIB_VECTOR_FST_H__
