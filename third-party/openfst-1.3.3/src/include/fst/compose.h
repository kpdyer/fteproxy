// compose.h

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
// Class to compute the composition of two FSTs

#ifndef FST_LIB_COMPOSE_H__
#define FST_LIB_COMPOSE_H__

#include <algorithm>
#include <string>
#include <vector>
using std::vector;

#include <fst/cache.h>
#include <fst/compose-filter.h>
#include <fst/lookahead-filter.h>
#include <fst/matcher.h>
#include <fst/state-table.h>
#include <fst/test-properties.h>


namespace fst {

// Delayed composition options templated on the arc type, the matcher,
// the composition filter, and the composition state table.  By
// default, the matchers, filter, and state table are constructed by
// composition. If set below, the user can instead pass in these
// objects; in that case, ComposeFst takes their ownership. This
// version controls composition implemented between generic Fst<Arc>
// types and a shared matcher type M for Fst<Arc>. This should be
// adequate for most applications, giving a reasonable tradeoff
// between efficiency and code sharing (but see ComposeFstImplOptions).
template <class A,
          class M = Matcher<Fst<A> >,
          class F = SequenceComposeFilter<M>,
          class T = GenericComposeStateTable<A, typename F::FilterState> >
struct ComposeFstOptions : public CacheOptions {
  M *matcher1;      // FST1 matcher (see matcher.h)
  M *matcher2;      // FST2 matcher
  F *filter;        // Composition filter (see compose-filter.h)
  T *state_table;   // Composition state table (see compose-state-table.h)

  explicit ComposeFstOptions(const CacheOptions &opts,
                             M *mat1 = 0, M *mat2 = 0,
                             F *filt = 0, T *sttable= 0)
      : CacheOptions(opts), matcher1(mat1), matcher2(mat2),
        filter(filt), state_table(sttable) {}

  ComposeFstOptions() : matcher1(0), matcher2(0), filter(0), state_table(0) {}
};


// Delayed composition options templated on the two matcher types, the
// composition filter, and the composition state table.  By default,
// the matchers, filter, and state table are constructed by
// composition. If set below, the user can instead pass in these
// objects; in that case, ComposeFst takes their ownership. This
// version controls composition implemented using arbitrary matchers
// (of the same Arc type but otherwise arbitrary Fst type). The user
// must ensure the matchers are compatible. These options permit the
// most efficient use, but shares the least code. This is for advanced
// use only in the most demanding or specialized applications that can
// benefit from it (o.w. prefer ComposeFstOptions).
template <class M1, class M2,
          class F = SequenceComposeFilter<M1, M2>,
          class T = GenericComposeStateTable<typename M1::Arc,
                                             typename F::FilterState> >
struct ComposeFstImplOptions : public CacheOptions {
  M1 *matcher1;     // FST1 matcher (see matcher.h)
  M2 *matcher2;     // FST2 matcher
  F *filter;        // Composition filter (see compose-filter.h)
  T *state_table;   // Composition state table (see compose-state-table.h)

  explicit ComposeFstImplOptions(const CacheOptions &opts,
                                 M1 *mat1 = 0, M2 *mat2 = 0,
                                 F *filt = 0, T *sttable= 0)
      : CacheOptions(opts), matcher1(mat1), matcher2(mat2),
        filter(filt), state_table(sttable) {}

  ComposeFstImplOptions()
  : matcher1(0), matcher2(0), filter(0), state_table(0) {}
};


// Implementation of delayed composition. This base class is
// common to the variants with different matchers, composition filters
// and state tables.
template <class A>
class ComposeFstImplBase : public CacheImpl<A> {
 public:
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::Properties;
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;

  using CacheBaseImpl< CacheState<A> >::HasStart;
  using CacheBaseImpl< CacheState<A> >::HasFinal;
  using CacheBaseImpl< CacheState<A> >::HasArcs;
  using CacheBaseImpl< CacheState<A> >::SetFinal;
  using CacheBaseImpl< CacheState<A> >::SetStart;

  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef CacheState<A> State;

  ComposeFstImplBase(const Fst<A> &fst1, const Fst<A> &fst2,
                     const CacheOptions &opts)
      : CacheImpl<A>(opts) {
    VLOG(2) << "ComposeFst(" << this << "): Begin";
    SetType("compose");

    if (!CompatSymbols(fst2.InputSymbols(), fst1.OutputSymbols())) {
      FSTERROR() << "ComposeFst: output symbol table of 1st argument "
                 << "does not match input symbol table of 2nd argument";
      SetProperties(kError, kError);
    }

    SetInputSymbols(fst1.InputSymbols());
    SetOutputSymbols(fst2.OutputSymbols());
  }

  ComposeFstImplBase(const ComposeFstImplBase<A> &impl)
      : CacheImpl<A>(impl, true) {
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
  }

  virtual ComposeFstImplBase<A> *Copy() = 0;

  virtual ~ComposeFstImplBase() {}

  StateId Start() {
    if (!HasStart()) {
      StateId start = ComputeStart();
      if (start != kNoStateId) {
        SetStart(start);
      }
    }
    return CacheImpl<A>::Start();
  }

  Weight Final(StateId s) {
    if (!HasFinal(s)) {
      Weight final = ComputeFinal(s);
      SetFinal(s, final);
    }
    return CacheImpl<A>::Final(s);
  }

  virtual void Expand(StateId s) = 0;

  size_t NumArcs(StateId s) {
    if (!HasArcs(s))
      Expand(s);
    return CacheImpl<A>::NumArcs(s);
  }

  size_t NumInputEpsilons(StateId s) {
    if (!HasArcs(s))
      Expand(s);
    return CacheImpl<A>::NumInputEpsilons(s);
  }

  size_t NumOutputEpsilons(StateId s) {
    if (!HasArcs(s))
      Expand(s);
    return CacheImpl<A>::NumOutputEpsilons(s);
  }

  void InitArcIterator(StateId s, ArcIteratorData<A> *data) {
    if (!HasArcs(s))
      Expand(s);
    CacheImpl<A>::InitArcIterator(s, data);
  }

 protected:
  virtual StateId ComputeStart() = 0;
  virtual Weight ComputeFinal(StateId s) = 0;
};


// Implementaion of delayed composition templated on the matchers (see
// matcher.h), composition filter (see compose-filter-inl.h) and
// the composition state table (see compose-state-table.h).
template <class M1, class M2, class F, class T>
class ComposeFstImpl : public ComposeFstImplBase<typename M1::Arc> {
  typedef typename M1::FST FST1;
  typedef typename M2::FST FST2;
  typedef typename M1::Arc Arc;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;
  typedef typename F::FilterState FilterState;
  typedef typename F::Matcher1 Matcher1;
  typedef typename F::Matcher2 Matcher2;

  using CacheBaseImpl<CacheState<Arc> >::SetArcs;
  using FstImpl<Arc>::SetType;
  using FstImpl<Arc>::SetProperties;

  typedef ComposeStateTuple<StateId, FilterState> StateTuple;

 public:
  ComposeFstImpl(const FST1 &fst1, const FST2 &fst2,
                 const ComposeFstImplOptions<M1, M2, F, T> &opts);

  ComposeFstImpl(const ComposeFstImpl<M1, M2, F, T> &impl)
      : ComposeFstImplBase<Arc>(impl),
        filter_(new F(*impl.filter_, true)),
        matcher1_(filter_->GetMatcher1()),
        matcher2_(filter_->GetMatcher2()),
        fst1_(matcher1_->GetFst()),
        fst2_(matcher2_->GetFst()),
        state_table_(new T(*impl.state_table_)),
        match_type_(impl.match_type_) {}

  ~ComposeFstImpl() {
    VLOG(2) << "ComposeFst(" << this
            << "): End: # of visited states: " << state_table_->Size();

    delete filter_;
    delete state_table_;
  }

  virtual ComposeFstImpl<M1, M2, F, T> *Copy() {
    return new ComposeFstImpl<M1, M2, F, T>(*this);
  }

  uint64 Properties() const { return Properties(kFstProperties); }

  // Set error if found; return FST impl properties.
  uint64 Properties(uint64 mask) const {
    if ((mask & kError) &&
        (fst1_.Properties(kError, false) ||
         fst2_.Properties(kError, false) ||
         (matcher1_->Properties(0) & kError) ||
         (matcher2_->Properties(0) & kError) |
         (filter_->Properties(0) & kError) ||
         state_table_->Error())) {
      SetProperties(kError, kError);
    }
    return FstImpl<Arc>::Properties(mask);
  }

  // Arranges it so that the first arg to OrderedExpand is the Fst
  // that will be matched on.
  void Expand(StateId s) {
    const StateTuple &tuple = state_table_->Tuple(s);
    StateId s1 = tuple.state_id1;
    StateId s2 = tuple.state_id2;
    filter_->SetState(s1, s2, tuple.filter_state);
    if (match_type_ == MATCH_OUTPUT ||
        (match_type_ == MATCH_BOTH &&
         internal::NumArcs(fst1_, s1) > internal::NumArcs(fst2_, s2)))
      OrderedExpand(s, fst1_, s1, fst2_, s2, matcher1_, false);
    else
      OrderedExpand(s, fst2_, s2, fst1_, s1, matcher2_, true);
  }

  const FST1 &GetFst1() { return fst1_; }
  const FST2 &GetFst2() { return fst2_; }
  M1 *GetMatcher1() { return matcher1_; }
  M2 *GetMatcher2() { return matcher2_; }
  F *GetFilter() { return filter_; }
  T *GetStateTable() { return state_table_; }

 private:
  // This does that actual matching of labels in the composition. The
  // arguments are ordered so matching is called on state 'sa' of
  // 'fsta' for each arc leaving state 'sb' of 'fstb'. The 'match_input' arg
  // determines whether the input or output label of arcs at 'sb' is
  // the one to match on.
  template <class FST, class Matcher>
  void OrderedExpand(StateId s, const Fst<Arc> &, StateId sa,
                     const FST &fstb, StateId sb,
                     Matcher *matchera,  bool match_input) {
    matchera->SetState(sa);

    // First process non-consuming symbols (e.g., epsilons) on FSTA.
    Arc loop(match_input ? 0 : kNoLabel, match_input ? kNoLabel : 0,
           Weight::One(), sb);
    MatchArc(s, matchera, loop, match_input);

    // Then process matches on FSTB.
    for (ArcIterator<FST> iterb(fstb, sb); !iterb.Done(); iterb.Next())
      MatchArc(s, matchera, iterb.Value(), match_input);

    SetArcs(s);
  }

  // Matches a single transition from 'fstb' against 'fata' at 's'.
  template <class Matcher>
  void MatchArc(StateId s, Matcher *matchera,
                const Arc &arc, bool match_input) {
    if (matchera->Find(match_input ? arc.olabel : arc.ilabel)) {
      for (; !matchera->Done(); matchera->Next()) {
        Arc arca = matchera->Value();
        Arc arcb = arc;
        if (match_input) {
          const FilterState &f = filter_->FilterArc(&arcb, &arca);
          if (f != FilterState::NoState())
            AddArc(s, arcb, arca, f);
        } else {
          const FilterState &f = filter_->FilterArc(&arca, &arcb);
          if (f != FilterState::NoState())
            AddArc(s, arca, arcb, f);
        }
      }
    }
  }

  // Add a matching transition at 's'.
   void AddArc(StateId s, const Arc &arc1, const Arc &arc2,
               const FilterState &f) {
    StateTuple tuple(arc1.nextstate, arc2.nextstate, f);
    Arc oarc(arc1.ilabel, arc2.olabel, Times(arc1.weight, arc2.weight),
           state_table_->FindState(tuple));
    CacheImpl<Arc>::PushArc(s, oarc);
  }

  StateId ComputeStart() {
    StateId s1 = fst1_.Start();
    if (s1 == kNoStateId)
      return kNoStateId;

    StateId s2 = fst2_.Start();
    if (s2 == kNoStateId)
      return kNoStateId;

    const FilterState &f = filter_->Start();
    StateTuple tuple(s1, s2, f);
    return state_table_->FindState(tuple);
  }

  Weight ComputeFinal(StateId s) {
    const StateTuple &tuple = state_table_->Tuple(s);
    StateId s1 = tuple.state_id1;
    Weight final1 = internal::Final(fst1_, s1);
    if (final1 == Weight::Zero())
      return final1;

    StateId s2 = tuple.state_id2;
    Weight final2 = internal::Final(fst2_, s2);
    if (final2 == Weight::Zero())
      return final2;

    filter_->SetState(s1, s2, tuple.filter_state);
    filter_->FilterFinal(&final1, &final2);
    return Times(final1, final2);
  }

  // Identifies and verifies the capabilities of the matcher to be used for
  // composition.
  void SetMatchType();

  F *filter_;
  Matcher1 *matcher1_;
  Matcher2 *matcher2_;
  const FST1 &fst1_;
  const FST2 &fst2_;
  T *state_table_;

  MatchType match_type_;

  void operator=(const ComposeFstImpl<M1, M2, F, T> &);  // disallow
};

template <class M1, class M2, class F, class T> inline
ComposeFstImpl<M1, M2, F, T>::ComposeFstImpl(
    const FST1 &fst1, const FST2 &fst2,
    const ComposeFstImplOptions<M1, M2, F, T> &opts)
    : ComposeFstImplBase<Arc>(fst1, fst2, opts),
      filter_(opts.filter ? opts.filter :
              new F(fst1, fst2, opts.matcher1, opts.matcher2)),
      matcher1_(filter_->GetMatcher1()),
      matcher2_(filter_->GetMatcher2()),
      fst1_(matcher1_->GetFst()),
      fst2_(matcher2_->GetFst()),
      state_table_(opts.state_table ? opts.state_table :
                   new T(fst1_, fst2_)) {
  SetMatchType();
  if (match_type_ == MATCH_NONE)
    SetProperties(kError, kError);
  VLOG(2) << "ComposeFst(" << this << "): Match type: "
          << (match_type_ == MATCH_OUTPUT ? "output" :
              (match_type_ == MATCH_INPUT ? "input" :
               (match_type_ == MATCH_BOTH ? "both" :
                (match_type_ == MATCH_NONE ? "none" : "unknown"))));

  uint64 fprops1 = fst1.Properties(kFstProperties, false);
  uint64 fprops2 = fst2.Properties(kFstProperties, false);
  uint64 mprops1 = matcher1_->Properties(fprops1);
  uint64 mprops2 = matcher2_->Properties(fprops2);
  uint64 cprops = ComposeProperties(mprops1, mprops2);
  SetProperties(filter_->Properties(cprops), kCopyProperties);
  if (state_table_->Error()) SetProperties(kError, kError);
  VLOG(2) << "ComposeFst(" << this << "): Initialized";
}

template <class M1, class M2, class F, class T>
void ComposeFstImpl<M1, M2, F, T>::SetMatchType() {
  MatchType type1 = matcher1_->Type(false);
  MatchType type2 = matcher2_->Type(false);
  uint32 flags1 = matcher1_->Flags();
  uint32 flags2 = matcher2_->Flags();
  if (flags1 & flags2 & kRequireMatch) {
    FSTERROR() << "ComposeFst: only one argument can require matching.";
    match_type_ = MATCH_NONE;
  } else if (flags1 & kRequireMatch) {
    if (matcher1_->Type(true) != MATCH_OUTPUT) {
      FSTERROR() << "ComposeFst: 1st argument requires matching but cannot.";
      match_type_ = MATCH_NONE;
    }
    match_type_ = MATCH_OUTPUT;
  } else if (flags2 & kRequireMatch) {
    if (matcher2_->Type(true) != MATCH_INPUT) {
      FSTERROR() << "ComposeFst: 2nd argument requires matching but cannot.";
      match_type_ = MATCH_NONE;
    }
    match_type_ = MATCH_INPUT;
  } else if (flags1 & flags2 & kPreferMatch &&
             type1 == MATCH_OUTPUT && type2  == MATCH_INPUT) {
    match_type_ = MATCH_BOTH;
  } else if (flags1 & kPreferMatch && type1 == MATCH_OUTPUT) {
    match_type_ = MATCH_OUTPUT;
  } else if  (flags2 & kPreferMatch && type2 == MATCH_INPUT) {
    match_type_ = MATCH_INPUT;
  } else if (type1 == MATCH_OUTPUT && type2  == MATCH_INPUT) {
    match_type_ = MATCH_BOTH;
  } else if (type1 == MATCH_OUTPUT) {
    match_type_ = MATCH_OUTPUT;
  } else if (type2 == MATCH_INPUT) {
    match_type_ = MATCH_INPUT;
  } else if (flags1 & kPreferMatch && matcher1_->Type(true) == MATCH_OUTPUT) {
    match_type_ = MATCH_OUTPUT;
  } else if  (flags2 & kPreferMatch && matcher2_->Type(true) == MATCH_INPUT) {
    match_type_ = MATCH_INPUT;
  } else if (matcher1_->Type(true) == MATCH_OUTPUT) {
    match_type_ = MATCH_OUTPUT;
  } else if (matcher2_->Type(true) == MATCH_INPUT) {
    match_type_ = MATCH_INPUT;
  } else {
    FSTERROR() << "ComposeFst: 1st argument cannot match on output labels "
               << "and 2nd argument cannot match on input labels (sort?).";
    match_type_ = MATCH_NONE;
  }
}


// Computes the composition of two transducers. This version is a
// delayed Fst. If FST1 transduces string x to y with weight a and FST2
// transduces y to z with weight b, then their composition transduces
// string x to z with weight Times(x, z).
//
// The output labels of the first transducer or the input labels of
// the second transducer must be sorted (with the default matcher).
// The weights need to form a commutative semiring (valid for
// TropicalWeight and LogWeight).
//
// Complexity:
// Assuming the first FST is unsorted and the second is sorted:
// - Time: O(v1 v2 d1 (log d2 + m2)),
// - Space: O(v1 v2)
// where vi = # of states visited, di = maximum out-degree, and mi the
// maximum multiplicity of the states visited for the ith
// FST. Constant time and space to visit an input state or arc is
// assumed and exclusive of caching.
//
// Caveats:
// - ComposeFst does not trim its output (since it is a delayed operation).
// - The efficiency of composition can be strongly affected by several factors:
//   - the choice of which tnansducer is sorted - prefer sorting the FST
//     that has the greater average out-degree.
//   - the amount of non-determinism
//   - the presence and location of epsilon transitions - avoid epsilon
//     transitions on the output side of the first transducer or
//     the input side of the second transducer or prefer placing
//     them later in a path since they delay matching and can
//     introduce non-coaccessible states and transitions.
//
// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A>
class ComposeFst : public ImplToFst< ComposeFstImplBase<A> > {
 public:
  friend class ArcIterator< ComposeFst<A> >;
  friend class StateIterator< ComposeFst<A> >;

  typedef A Arc;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef CacheState<A> State;
  typedef ComposeFstImplBase<A> Impl;

  using ImplToFst<Impl>::SetImpl;

  // Compose specifying only caching options.
  ComposeFst(const Fst<A> &fst1, const Fst<A> &fst2,
             const CacheOptions &opts = CacheOptions())
      : ImplToFst<Impl>(CreateBase(fst1, fst2, opts)) {}

  // Compose specifying one shared matcher type M.  Requires input
  // Fsts and matcher FST type (M::FST) be Fst<A>. Recommended for
  // best code-sharing and matcher compatiblity.
  template <class M, class F, class T>
  ComposeFst(const Fst<A> &fst1, const Fst<A> &fst2,
             const ComposeFstOptions<A, M, F, T> &opts)
      : ImplToFst<Impl>(CreateBase1(fst1, fst2, opts)) {}

  // Compose specifying two matcher types M1 and M2.  Requires input
  // Fsts (of the same Arc type but o.w. arbitrary) match the
  // corresponding matcher FST types (M1::FST, M2::FST). Recommended
  // only for advanced use in demanding or specialized applications
  // due to potential code bloat and matcher incompatibilities.
  template <class M1, class M2, class F, class T>
  ComposeFst(const typename M1::FST &fst1, const typename M2::FST &fst2,
             const ComposeFstImplOptions<M1, M2, F, T> &opts)
      : ImplToFst<Impl>(CreateBase2(fst1, fst2, opts)) {}

  // See Fst<>::Copy() for doc.
  ComposeFst(const ComposeFst<A> &fst, bool safe = false) {
    if (safe)
      SetImpl(fst.GetImpl()->Copy());
    else
      SetImpl(fst.GetImpl(), false);
  }

  // Get a copy of this ComposeFst. See Fst<>::Copy() for further doc.
  virtual ComposeFst<A> *Copy(bool safe = false) const {
    return new ComposeFst<A>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

 protected:
  ComposeFst() {}

  // Create compose implementation specifying two matcher types.
  template <class M1, class M2, class F, class T>
  static Impl *CreateBase2(
      const typename M1::FST &fst1, const typename M2::FST &fst2,
      const ComposeFstImplOptions<M1, M2, F, T> &opts) {
    Impl *impl = new ComposeFstImpl<M1, M2, F, T>(fst1, fst2, opts);
    if (!(Weight::Properties() & kCommutative)) {
      int64 props1 = fst1.Properties(kUnweighted, true);
      int64 props2 = fst2.Properties(kUnweighted, true);
      if (!(props1 & kUnweighted) && !(props2 & kUnweighted)) {
        FSTERROR() << "ComposeFst: Weights must be a commutative semiring: "
                   << Weight::Type();
        impl->SetProperties(kError, kError);
      }
    }
    return impl;
  }

  // Create compose implementation specifying one matcher type.
  //  Requires input Fsts and matcher FST type (M::FST) be Fst<A>
  template <class M, class F, class T>
  static Impl *CreateBase1(const Fst<A> &fst1, const Fst<A> &fst2,
                           const ComposeFstOptions<A, M, F, T> &opts) {
    ComposeFstImplOptions<M, M, F, T> nopts(opts, opts.matcher1, opts.matcher2,
                                            opts.filter, opts.state_table);
    return CreateBase2(fst1, fst2, nopts);
  }

  // Create compose implementation specifying no matcher type.
  static Impl *CreateBase(const Fst<A> &fst1, const Fst<A> &fst2,
                          const CacheOptions &opts) {
    switch (LookAheadMatchType(fst1, fst2)) {  // Check for lookahead matchers
      default:
      case MATCH_NONE: {     // Default composition (no look-ahead)
        VLOG(2) << "ComposeFst: Default composition (no look-ahead)";
        ComposeFstOptions<Arc> nopts(opts);
        return CreateBase1(fst1, fst2, nopts);
      }
      case MATCH_OUTPUT: {   // Lookahead on fst1
        VLOG(2) << "ComposeFst: Lookahead on fst1";
        typedef typename DefaultLookAhead<Arc, MATCH_OUTPUT>::FstMatcher M;
        typedef typename DefaultLookAhead<Arc, MATCH_OUTPUT>::ComposeFilter F;
        ComposeFstOptions<Arc, M, F> nopts(opts);
        return CreateBase1(fst1, fst2, nopts);
      }
      case MATCH_INPUT: {    // Lookahead on fst2
        VLOG(2) << "ComposeFst: Lookahead on fst2";
        typedef typename DefaultLookAhead<Arc, MATCH_INPUT>::FstMatcher M;
        typedef typename DefaultLookAhead<Arc, MATCH_INPUT>::ComposeFilter F;
        ComposeFstOptions<Arc, M, F> nopts(opts);
        return CreateBase1(fst1, fst2, nopts);
      }
    }
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const ComposeFst<A> &fst);  // disallow
};


// Specialization for ComposeFst.
template<class A>
class StateIterator< ComposeFst<A> >
    : public CacheStateIterator< ComposeFst<A> > {
 public:
  explicit StateIterator(const ComposeFst<A> &fst)
      : CacheStateIterator< ComposeFst<A> >(fst, fst.GetImpl()) {}
};


// Specialization for ComposeFst.
template <class A>
class ArcIterator< ComposeFst<A> >
    : public CacheArcIterator< ComposeFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const ComposeFst<A> &fst, StateId s)
      : CacheArcIterator< ComposeFst<A> >(fst.GetImpl(), s) {
    if (!fst.GetImpl()->HasArcs(s))
      fst.GetImpl()->Expand(s);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};

template <class A> inline
void ComposeFst<A>::InitStateIterator(StateIteratorData<A> *data) const {
  data->base = new StateIterator< ComposeFst<A> >(*this);
}

// Useful alias when using StdArc.
typedef ComposeFst<StdArc> StdComposeFst;

enum ComposeFilter { AUTO_FILTER, SEQUENCE_FILTER, ALT_SEQUENCE_FILTER,
                     MATCH_FILTER };

struct ComposeOptions {
  bool connect;  // Connect output
  ComposeFilter filter_type;  // Which pre-defined filter to use

  ComposeOptions(bool c, ComposeFilter ft = AUTO_FILTER)
      : connect(c), filter_type(ft) {}
  ComposeOptions() : connect(true), filter_type(AUTO_FILTER) {}
};

// Computes the composition of two transducers. This version writes
// the composed FST into a MurableFst. If FST1 transduces string x to
// y with weight a and FST2 transduces y to z with weight b, then
// their composition transduces string x to z with weight
// Times(x, z).
//
// The output labels of the first transducer or the input labels of
// the second transducer must be sorted.  The weights need to form a
// commutative semiring (valid for TropicalWeight and LogWeight).
//
// Complexity:
// Assuming the first FST is unsorted and the second is sorted:
// - Time: O(V1 V2 D1 (log D2 + M2)),
// - Space: O(V1 V2 D1 M2)
// where Vi = # of states, Di = maximum out-degree, and Mi is
// the maximum multiplicity for the ith FST.
//
// Caveats:
// - Compose trims its output.
// - The efficiency of composition can be strongly affected by several factors:
//   - the choice of which tnansducer is sorted - prefer sorting the FST
//     that has the greater average out-degree.
//   - the amount of non-determinism
//   - the presence and location of epsilon transitions - avoid epsilon
//     transitions on the output side of the first transducer or
//     the input side of the second transducer or prefer placing
//     them later in a path since they delay matching and can
//     introduce non-coaccessible states and transitions.
template<class Arc>
void Compose(const Fst<Arc> &ifst1, const Fst<Arc> &ifst2,
             MutableFst<Arc> *ofst,
             const ComposeOptions &opts = ComposeOptions()) {
  typedef Matcher< Fst<Arc> > M;

  if (opts.filter_type == AUTO_FILTER) {
     CacheOptions nopts;
     nopts.gc_limit = 0;  // Cache only the last state for fastest copy.
     *ofst = ComposeFst<Arc>(ifst1, ifst2, nopts);
  } else if (opts.filter_type == SEQUENCE_FILTER) {
    ComposeFstOptions<Arc> copts;
    copts.gc_limit = 0;  // Cache only the last state for fastest copy.
    *ofst = ComposeFst<Arc>(ifst1, ifst2, copts);
  } else if (opts.filter_type == ALT_SEQUENCE_FILTER) {
    ComposeFstOptions<Arc, M,  AltSequenceComposeFilter<M> > copts;
    copts.gc_limit = 0;  // Cache only the last state for fastest copy.
    *ofst = ComposeFst<Arc>(ifst1, ifst2, copts);
  } else if (opts.filter_type == MATCH_FILTER) {
    ComposeFstOptions<Arc, M,  MatchComposeFilter<M> > copts;
    copts.gc_limit = 0;  // Cache only the last state for fastest copy.
    *ofst = ComposeFst<Arc>(ifst1, ifst2, copts);
  }

  if (opts.connect)
    Connect(ofst);
}

}  // namespace fst

#endif  // FST_LIB_COMPOSE_H__
