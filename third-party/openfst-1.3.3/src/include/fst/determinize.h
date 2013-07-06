// determinize.h


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
// Functions and classes to determinize an FST.

#ifndef FST_LIB_DETERMINIZE_H__
#define FST_LIB_DETERMINIZE_H__

#include <algorithm>
#include <climits>
#include <tr1/unordered_map>
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;
#include <map>
#include <fst/slist.h>
#include <string>
#include <vector>
using std::vector;

#include <fst/arc-map.h>
#include <fst/cache.h>
#include <fst/bi-table.h>
#include <fst/factor-weight.h>
#include <fst/prune.h>
#include <fst/test-properties.h>


namespace fst {

//
// COMMON DIVISORS - these are used in determinization to compute
// the transition weights. In the simplest case, it is just the same
// as the semiring Plus(). However, other choices permit more efficient
// determinization when the output contains strings.
//

// The default common divisor uses the semiring Plus.
template <class W>
class DefaultCommonDivisor {
 public:
  typedef W Weight;

  W operator()(const W &w1, const W &w2) const { return Plus(w1, w2); }
};


// The label common divisor for a (left) string semiring selects a
// single letter common prefix or the empty string. This is used in
// the determinization of output strings so that at most a single
// letter will appear in the output of a transtion.
template <typename L, StringType S>
class LabelCommonDivisor {
 public:
  typedef StringWeight<L, S> Weight;

  Weight operator()(const Weight &w1, const Weight &w2) const {
    StringWeightIterator<L, S> iter1(w1);
    StringWeightIterator<L, S> iter2(w2);

    if (!(StringWeight<L, S>::Properties() & kLeftSemiring)) {
      FSTERROR() << "LabelCommonDivisor: Weight needs to be left semiring";
      return Weight::NoWeight();
    } else if (w1.Size() == 0 || w2.Size() == 0) {
      return Weight::One();
    } else if (w1 == Weight::Zero()) {
      return Weight(iter2.Value());
    } else if (w2 == Weight::Zero()) {
      return Weight(iter1.Value());
    } else if (iter1.Value() == iter2.Value()) {
      return Weight(iter1.Value());
    } else {
      return Weight::One();
    }
  }
};


// The gallic common divisor uses the label common divisor on the
// string component and the template argument D common divisor on the
// weight component, which defaults to the default common divisor.
template <class L, class W, StringType S, class D = DefaultCommonDivisor<W> >
class GallicCommonDivisor {
 public:
  typedef GallicWeight<L, W, S> Weight;

  Weight operator()(const Weight &w1, const Weight &w2) const {
    return Weight(label_common_divisor_(w1.Value1(), w2.Value1()),
                  weight_common_divisor_(w1.Value2(), w2.Value2()));
  }

 private:
  LabelCommonDivisor<L, S> label_common_divisor_;
  D weight_common_divisor_;
};


// Represents an element in a subset
template <class A>
struct DeterminizeElement {
  typedef typename A::StateId StateId;
  typedef typename A::Weight Weight;

  DeterminizeElement() {}

  DeterminizeElement(StateId s, Weight w) : state_id(s), weight(w) {}

  bool operator==(const DeterminizeElement<A> & element) const {
    return state_id == element.state_id && weight == element.weight;
  }

  bool operator<(const DeterminizeElement<A> & element) const {
    return state_id < element.state_id ||
        (state_id == element.state_id && weight == element.weight);
  }

  StateId state_id;  // Input state Id
  Weight weight;     // Residual weight
};


//
// DETERMINIZE FILTERS - these can be used in determinization to compute
// transformations on the subsets prior to their being added as destination
// states. The filter operates on a map between a label and the
// corresponding destination subsets. The possibly modified map is
// then used to construct the destination states for arcs exiting state 's'.
// It must define the ordered map type LabelMap and have a default
// and copy constructor.

// A determinize filter that does not modify its input.
template <class Arc>
struct IdentityDeterminizeFilter {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef slist< DeterminizeElement<Arc> > Subset;
  typedef map<Label, Subset*> LabelMap;

  static uint64 Properties(uint64 props) { return props; }

  void operator()(StateId s, LabelMap *label_map) {}
};


//
// DETERMINIZATION STATE TABLES
//
// The determiziation state table has the form:
//
// template <class Arc>
// class DeterminizeStateTable {
//  public:
//   typedef typename Arc::StateId StateId;
//   typedef DeterminizeElement<Arc> Element;
//   typedef slist<Element> Subset;
//
//   // Required constuctor
//   DeterminizeStateTable();
//
//   // Required copy constructor that does not copy state
//   DeterminizeStateTable(const DeterminizeStateTable<A,P> &table);
//
//   // Lookup state ID by subset (not depending of the element order).
//   // If it doesn't exist, then add it.  FindState takes
//   // ownership of the subset argument (so that it doesn't have to
//   // copy it if it creates a new state).
//   StateId FindState(Subset *subset);
//
//   // Lookup subset by ID.
//   const Subset *FindSubset(StateId id) const;
// };
//

// The default determinization state table based on the
// compact hash bi-table.
template <class Arc>
class DefaultDeterminizeStateTable {
 public:
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;
  typedef DeterminizeElement<Arc> Element;
  typedef slist<Element> Subset;

  explicit DefaultDeterminizeStateTable(size_t table_size = 0)
      : table_size_(table_size),
        subsets_(table_size_, new SubsetKey(), new SubsetEqual(&elements_)) { }

  DefaultDeterminizeStateTable(const DefaultDeterminizeStateTable<Arc> &table)
      : table_size_(table.table_size_),
        subsets_(table_size_, new SubsetKey(), new SubsetEqual(&elements_)) { }

  ~DefaultDeterminizeStateTable() {
    for (StateId s = 0; s < subsets_.Size(); ++s)
      delete subsets_.FindEntry(s);
  }

  // Finds the state corresponding to a subset. Only creates a new
  // state if the subset is not found. FindState takes ownership of
  // the subset argument (so that it doesn't have to copy it if it
  // creates a new state).
  StateId FindState(Subset *subset) {
    StateId ns = subsets_.Size();
    StateId s = subsets_.FindId(subset);
    if (s != ns) delete subset;  // subset found
    return s;
  }

  const Subset* FindSubset(StateId s) { return subsets_.FindEntry(s); }

 private:
  // Comparison object for hashing Subset(s). Subsets are not sorted in this
  // implementation, so ordering must not be assumed in the equivalence
  // test.
  class SubsetEqual {
   public:
    SubsetEqual() {  // needed for compilation but should never be called
      FSTERROR() << "SubsetEqual: default constructor not implemented";
    }

    // Constructor takes vector needed to check equality. See immediately
    // below for constraints on it.
    explicit SubsetEqual(vector<Element *> *elements)
        : elements_(elements) {}

    // At each call to operator(), the elements_ vector should contain
    // only NULLs. When this operator returns, elements_ will still
    // have this property.
    bool operator()(Subset* subset1, Subset* subset2) const {
      if (!subset1 && !subset2)
        return true;
      if ((subset1 && !subset2) || (!subset1 && subset2))
        return false;

      if (subset1->size() != subset2->size())
        return false;

      // Loads first subset elements in element vector.
      for (typename Subset::iterator iter1 = subset1->begin();
           iter1 != subset1->end();
           ++iter1) {
        Element &element1 = *iter1;
        while (elements_->size() <= element1.state_id)
          elements_->push_back(0);
        (*elements_)[element1.state_id] = &element1;
      }

      // Checks second subset matches first via element vector.
      for (typename Subset::iterator iter2 = subset2->begin();
           iter2 != subset2->end();
           ++iter2) {
        Element &element2 = *iter2;
        while (elements_->size() <= element2.state_id)
          elements_->push_back(0);
        Element *element1 = (*elements_)[element2.state_id];
        if (!element1 || element1->weight != element2.weight) {
          // Mismatch found. Resets element vector before returning false.
          for (typename Subset::iterator iter1 = subset1->begin();
               iter1 != subset1->end();
               ++iter1)
            (*elements_)[iter1->state_id] = 0;
          return false;
        } else {
          (*elements_)[element2.state_id] = 0;  // Clears entry
        }
      }
      return true;
    }
   private:
    vector<Element *> *elements_;
  };

  // Hash function for Subset to Fst states. Subset elements are not
  // sorted in this implementation, so the hash must be invariant
  // under subset reordering.
  class SubsetKey {
   public:
    size_t operator()(const Subset* subset) const {
      size_t hash = 0;
      if (subset) {
        for (typename Subset::const_iterator iter = subset->begin();
             iter != subset->end();
             ++iter) {
          const Element &element = *iter;
          int lshift = element.state_id % (CHAR_BIT * sizeof(size_t) - 1) + 1;
          int rshift = CHAR_BIT * sizeof(size_t) - lshift;
          size_t n = element.state_id;
          hash ^= n << lshift ^ n >> rshift ^ element.weight.Hash();
        }
      }
      return hash;
    }
  };

  size_t table_size_;

  typedef CompactHashBiTable<StateId, Subset *,
                             SubsetKey, SubsetEqual, HS_STL>  SubsetTable;

  SubsetTable subsets_;
  vector<Element *> elements_;

  void operator=(const DefaultDeterminizeStateTable<Arc> &);  // disallow
};

// Options for finite-state transducer determinization templated on
// the arc type, common divisor, the determinization filter and the
// state table.  DeterminizeFst takes ownership of the determinization
// filter and state table if provided.
template <class Arc,
          class D = DefaultCommonDivisor<typename Arc::Weight>,
          class F = IdentityDeterminizeFilter<Arc>,
          class T = DefaultDeterminizeStateTable<Arc> >
struct DeterminizeFstOptions : CacheOptions {
  typedef typename Arc::Label Label;
  float delta;                // Quantization delta for subset weights
  Label subsequential_label;  // Label used for residual final output
                              // when producing subsequential transducers.
  F *filter;                  // Determinization filter
  T *state_table;             // Determinization state table

  explicit DeterminizeFstOptions(const CacheOptions &opts,
                                 float del = kDelta, Label lab = 0,
                                 F *filt = 0,
                                 T *table = 0)
      : CacheOptions(opts), delta(del), subsequential_label(lab),
        filter(filt), state_table(table) {}

  explicit DeterminizeFstOptions(float del = kDelta, Label lab = 0,
                                 F *filt = 0, T *table = 0)
      : delta(del), subsequential_label(lab), filter(filt),
        state_table(table) {}
};

// Implementation of delayed DeterminizeFst. This base class is
// common to the variants that implement acceptor and transducer
// determinization.
template <class A>
class DeterminizeFstImplBase : public CacheImpl<A> {
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

  template <class D, class F, class T>
  DeterminizeFstImplBase(const Fst<A> &fst,
                         const DeterminizeFstOptions<A, D, F, T> &opts)
      : CacheImpl<A>(opts), fst_(fst.Copy()) {
    SetType("determinize");
    uint64 iprops = fst.Properties(kFstProperties, false);
    uint64 dprops = DeterminizeProperties(iprops,
                                          opts.subsequential_label != 0);
    SetProperties(F::Properties(dprops), kCopyProperties);
    SetInputSymbols(fst.InputSymbols());
    SetOutputSymbols(fst.OutputSymbols());
  }

  DeterminizeFstImplBase(const DeterminizeFstImplBase<A> &impl)
      : CacheImpl<A>(impl),
        fst_(impl.fst_->Copy(true)) {
    SetType("determinize");
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
  }

  virtual ~DeterminizeFstImplBase() { delete fst_; }

  virtual DeterminizeFstImplBase<A> *Copy() = 0;

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

  virtual StateId ComputeStart() = 0;

  virtual Weight ComputeFinal(StateId s) = 0;

  const Fst<A> &GetFst() const { return *fst_; }

 private:
  const Fst<A> *fst_;            // Input Fst

  void operator=(const DeterminizeFstImplBase<A> &);  // disallow
};


// Implementation of delayed determinization for weighted acceptors.
// It is templated on the arc type A and the common divisor D.
template <class A, class D, class F, class T>
class DeterminizeFsaImpl : public DeterminizeFstImplBase<A> {
 public:
  using FstImpl<A>::SetProperties;
  using DeterminizeFstImplBase<A>::GetFst;
  using DeterminizeFstImplBase<A>::SetArcs;

  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef DeterminizeElement<A> Element;
  typedef slist<Element> Subset;
  typedef typename F::LabelMap LabelMap;

  DeterminizeFsaImpl(const Fst<A> &fst,
                     const vector<Weight> *in_dist, vector<Weight> *out_dist,
                     const DeterminizeFstOptions<A, D, F, T> &opts)
      : DeterminizeFstImplBase<A>(fst, opts),
        delta_(opts.delta),
        in_dist_(in_dist),
        out_dist_(out_dist),
        filter_(opts.filter ? opts.filter : new F()),
        state_table_(opts.state_table ? opts.state_table : new T()) {
    if (!fst.Properties(kAcceptor, true)) {
      FSTERROR()  << "DeterminizeFst: argument not an acceptor";
      SetProperties(kError, kError);
    }
    if (!(Weight::Properties() & kLeftSemiring)) {
      FSTERROR() << "DeterminizeFst: Weight needs to be left distributive: "
                 << Weight::Type();
      SetProperties(kError, kError);
    }
    if (out_dist_)
      out_dist_->clear();
  }

  DeterminizeFsaImpl(const DeterminizeFsaImpl<A, D, F, T> &impl)
      : DeterminizeFstImplBase<A>(impl),
        delta_(impl.delta_),
        in_dist_(0),
        out_dist_(0),
        filter_(new F(*impl.filter_)),
        state_table_(new T(*impl.state_table_)) {
    if (impl.out_dist_) {
      FSTERROR() << "DeterminizeFsaImpl: cannot copy with out_dist vector";
      SetProperties(kError, kError);
    }
  }

  virtual ~DeterminizeFsaImpl() {
    delete filter_;
    delete state_table_;
  }

  virtual DeterminizeFsaImpl<A, D, F, T> *Copy() {
    return new DeterminizeFsaImpl<A, D, F, T>(*this);
  }

  uint64 Properties() const { return Properties(kFstProperties); }

  // Set error if found; return FST impl properties.
  uint64 Properties(uint64 mask) const {
    if ((mask & kError) && (GetFst().Properties(kError, false)))
      SetProperties(kError, kError);
    return FstImpl<A>::Properties(mask);
  }

  virtual StateId ComputeStart() {
    StateId s = GetFst().Start();
    if (s == kNoStateId)
      return kNoStateId;
    Element element(s, Weight::One());
    Subset *subset = new Subset;
    subset->push_front(element);
    return FindState(subset);
  }

  virtual Weight ComputeFinal(StateId s) {
    const Subset *subset = state_table_->FindSubset(s);
    Weight final = Weight::Zero();
    for (typename Subset::const_iterator siter = subset->begin();
         siter != subset->end();
         ++siter) {
      const Element &element = *siter;
      final = Plus(final, Times(element.weight,
                                GetFst().Final(element.state_id)));
      if (!final.Member())
        SetProperties(kError, kError);
    }
    return final;
  }

  StateId FindState(Subset *subset) {
    StateId s = state_table_->FindState(subset);
    if (in_dist_ && out_dist_->size() <= s)
      out_dist_->push_back(ComputeDistance(subset));
    return s;
  }

  // Compute distance from a state to the final states in the DFA
  // given the distances in the NFA.
  Weight ComputeDistance(const Subset *subset) {
    Weight outd = Weight::Zero();
    for (typename Subset::const_iterator siter = subset->begin();
         siter != subset->end(); ++siter) {
      const Element &element = *siter;
      Weight ind = element.state_id < in_dist_->size() ?
          (*in_dist_)[element.state_id] : Weight::Zero();
      outd = Plus(outd, Times(element.weight, ind));
    }
    return outd;
  }

  // Computes the outgoing transitions from a state, creating new destination
  // states as needed.
  virtual void Expand(StateId s) {

    LabelMap label_map;
    LabelSubsets(s, &label_map);

    for (typename LabelMap::iterator liter = label_map.begin();
         liter != label_map.end();
         ++liter)
      AddArc(s, liter->first, liter->second);
    SetArcs(s);
  }

 private:
  // Constructs destination subsets per label. At return, subset
  // element weights include the input automaton label weights and the
  // subsets may contain duplicate states.
  void LabelSubsets(StateId s, LabelMap *label_map) {
    const Subset *src_subset = state_table_->FindSubset(s);

    for (typename Subset::const_iterator siter = src_subset->begin();
         siter != src_subset->end();
         ++siter) {
      const Element &src_element = *siter;
      for (ArcIterator< Fst<A> > aiter(GetFst(), src_element.state_id);
           !aiter.Done();
           aiter.Next()) {
        const A &arc = aiter.Value();
        Element dest_element(arc.nextstate,
                             Times(src_element.weight, arc.weight));

        // The LabelMap may be a e.g. multimap with more complex
        // determinization filters, so we insert efficiently w/o using [].
        typename LabelMap::iterator liter = label_map->lower_bound(arc.ilabel);
        Subset* dest_subset;
        if (liter == label_map->end() || liter->first != arc.ilabel) {
          dest_subset = new Subset;
          label_map->insert(liter, make_pair(arc.ilabel, dest_subset));
        } else {
          dest_subset = liter->second;
        }

        dest_subset->push_front(dest_element);
      }
    }
    // Applies the determinization filter
    (*filter_)(s, label_map);
  }

  // Adds an arc from state S to the destination state associated
  // with subset DEST_SUBSET (as created by LabelSubsets).
  void AddArc(StateId s, Label label, Subset *dest_subset) {
    A arc;
    arc.ilabel = label;
    arc.olabel = label;
    arc.weight = Weight::Zero();

    typename Subset::iterator oiter;
    for (typename Subset::iterator diter = dest_subset->begin();
         diter != dest_subset->end();) {
      Element &dest_element = *diter;
      // Computes label weight.
      arc.weight = common_divisor_(arc.weight, dest_element.weight);

      while (elements_.size() <= dest_element.state_id)
        elements_.push_back(0);
      Element *matching_element = elements_[dest_element.state_id];
      if (matching_element) {
        // Found duplicate state: sums state weight and deletes dup.
        matching_element->weight = Plus(matching_element->weight,
                                        dest_element.weight);
        if (!matching_element->weight.Member())
          SetProperties(kError, kError);
        ++diter;
        dest_subset->erase_after(oiter);
      } else {
        // Saves element so we can check for duplicate for this state.
        elements_[dest_element.state_id] = &dest_element;
        oiter = diter;
        ++diter;
      }
    }

    // Divides out label weight from destination subset elements.
    // Quantizes to ensure comparisons are effective.
    // Clears element vector.
    for (typename Subset::iterator diter = dest_subset->begin();
         diter != dest_subset->end();
         ++diter) {
      Element &dest_element = *diter;
      dest_element.weight = Divide(dest_element.weight, arc.weight,
                                   DIVIDE_LEFT);
      dest_element.weight = dest_element.weight.Quantize(delta_);
      elements_[dest_element.state_id] = 0;
    }

    arc.nextstate = FindState(dest_subset);
    CacheImpl<A>::PushArc(s, arc);
  }

  float delta_;                    // Quantization delta for subset weights
  const vector<Weight> *in_dist_;  // Distance to final NFA states
  vector<Weight> *out_dist_;       // Distance to final DFA states

  D common_divisor_;
  F *filter_;
  T *state_table_;

  vector<Element *> elements_;

  void operator=(const DeterminizeFsaImpl<A, D, F, T> &);  // disallow
};


// Implementation of delayed determinization for transducers.
// Transducer determinization is implemented by mapping the input to
// the Gallic semiring as an acceptor whose weights contain the output
// strings and using acceptor determinization above to determinize
// that acceptor.
template <class A, StringType S, class D, class F, class T>
class DeterminizeFstImpl : public DeterminizeFstImplBase<A> {
 public:
  using FstImpl<A>::SetProperties;
  using DeterminizeFstImplBase<A>::GetFst;
  using CacheBaseImpl< CacheState<A> >::GetCacheGc;
  using CacheBaseImpl< CacheState<A> >::GetCacheLimit;

  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;

  typedef ToGallicMapper<A, S> ToMapper;
  typedef FromGallicMapper<A, S> FromMapper;

  typedef typename ToMapper::ToArc ToArc;
  typedef ArcMapFst<A, ToArc, ToMapper> ToFst;
  typedef ArcMapFst<ToArc, A, FromMapper> FromFst;

  typedef GallicCommonDivisor<Label, Weight, S, D> CommonDivisor;
  typedef GallicFactor<Label, Weight, S> FactorIterator;

  DeterminizeFstImpl(const Fst<A> &fst,
                     const DeterminizeFstOptions<A, D, F, T> &opts)
      : DeterminizeFstImplBase<A>(fst, opts),
        delta_(opts.delta),
        subsequential_label_(opts.subsequential_label) {
     Init(GetFst());
  }

  DeterminizeFstImpl(const DeterminizeFstImpl<A, S, D, F, T> &impl)
      : DeterminizeFstImplBase<A>(impl),
        delta_(impl.delta_),
        subsequential_label_(impl.subsequential_label_) {
    Init(GetFst());
  }

  ~DeterminizeFstImpl() { delete from_fst_; }

  virtual DeterminizeFstImpl<A, S, D, F, T> *Copy() {
    return new DeterminizeFstImpl<A, S, D, F, T>(*this);
  }

  uint64 Properties() const { return Properties(kFstProperties); }

  // Set error if found; return FST impl properties.
  uint64 Properties(uint64 mask) const {
    if ((mask & kError) && (GetFst().Properties(kError, false) ||
                            from_fst_->Properties(kError, false)))
      SetProperties(kError, kError);
    return FstImpl<A>::Properties(mask);
  }

  virtual StateId ComputeStart() { return from_fst_->Start(); }

  virtual Weight ComputeFinal(StateId s) { return from_fst_->Final(s); }

  virtual void Expand(StateId s) {
    for (ArcIterator<FromFst> aiter(*from_fst_, s);
         !aiter.Done();
         aiter.Next())
      CacheImpl<A>::PushArc(s, aiter.Value());
    CacheImpl<A>::SetArcs(s);
  }

 private:
  // Initialization of transducer determinization implementation, which
  // is defined after DeterminizeFst since it calls it.
  void Init(const Fst<A> &fst);

  float delta_;
  Label subsequential_label_;
  FromFst *from_fst_;

  void operator=(const DeterminizeFstImpl<A, S, D, F, T> &);  // disallow
};


// Determinizes a weighted transducer. This version is a delayed
// Fst. The result will be an equivalent FST that has the property
// that no state has two transitions with the same input label.
// For this algorithm, epsilon transitions are treated as regular
// symbols (cf. RmEpsilon).
//
// The transducer must be functional. The weights must be (weakly)
// left divisible (valid for TropicalWeight and LogWeight for instance)
// and be zero-sum-free if for all a,b: (Plus(a, b) = 0 => a = b = 0.
//
// Complexity:
// - Determinizable: exponential (polynomial in the size of the output)
// - Non-determinizable) does not terminate
//
// The determinizable automata include all unweighted and all acyclic input.
//
// References:
// - Mehryar Mohri, "Finite-State Transducers in Language and Speech
//   Processing". Computational Linguistics, 23:2, 1997.
//
// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A>
class DeterminizeFst : public ImplToFst< DeterminizeFstImplBase<A> >  {
 public:
  friend class ArcIterator< DeterminizeFst<A> >;
  friend class StateIterator< DeterminizeFst<A> >;
  template <class B, StringType S, class D, class F, class T>
  friend class DeterminizeFstImpl;

  typedef A Arc;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef CacheState<A> State;
  typedef DeterminizeFstImplBase<A> Impl;

  using ImplToFst<Impl>::SetImpl;

  explicit DeterminizeFst(const Fst<A> &fst) {
    typedef DefaultCommonDivisor<Weight> D;
    typedef IdentityDeterminizeFilter<A> F;
    typedef DefaultDeterminizeStateTable<A> T;
    DeterminizeFstOptions<A, D, F, T> opts;
    if (fst.Properties(kAcceptor, true)) {
      // Calls implementation for acceptors.
      SetImpl(new DeterminizeFsaImpl<A, D, F, T>(fst, 0, 0, opts));
    } else {
      // Calls implementation for transducers.
      SetImpl(new
              DeterminizeFstImpl<A, STRING_LEFT_RESTRICT, D, F, T>(fst, opts));
    }
  }

  template <class D, class F, class T>
  DeterminizeFst(const Fst<A> &fst,
                 const DeterminizeFstOptions<A, D, F, T> &opts) {
    if (fst.Properties(kAcceptor, true)) {
      // Calls implementation for acceptors.
      SetImpl(new DeterminizeFsaImpl<A, D, F, T>(fst, 0, 0, opts));
    } else {
      // Calls implementation for transducers.
      SetImpl(new
              DeterminizeFstImpl<A, STRING_LEFT_RESTRICT, D, F, T>(fst, opts));
    }
  }

  // This acceptor-only version additionally computes the distance to
  // final states in the output if provided with those distances for the
  // input. Useful for e.g. unique N-shortest paths.
  template <class D, class F, class T>
  DeterminizeFst(const Fst<A> &fst,
                 const vector<Weight> *in_dist, vector<Weight> *out_dist,
                 const DeterminizeFstOptions<A, D, F, T> &opts) {
    if (!fst.Properties(kAcceptor, true)) {
      FSTERROR() << "DeterminizeFst:"
                 << " distance to final states computed for acceptors only";
      GetImpl()->SetProperties(kError, kError);
    }
    SetImpl(new DeterminizeFsaImpl<A, D, F, T>(fst, in_dist, out_dist, opts));
  }

  // See Fst<>::Copy() for doc.
  DeterminizeFst(const DeterminizeFst<A> &fst, bool safe = false) {
    if (safe)
      SetImpl(fst.GetImpl()->Copy());
    else
      SetImpl(fst.GetImpl(), false);
  }

  // Get a copy of this DeterminizeFst. See Fst<>::Copy() for further doc.
  virtual DeterminizeFst<A> *Copy(bool safe = false) const {
    return new DeterminizeFst<A>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const DeterminizeFst<A> &fst);  // Disallow
};


// Initialization of transducer determinization implementation. which
// is defined after DeterminizeFst since it calls it.
template <class A, StringType S, class D, class F, class T>
void DeterminizeFstImpl<A, S, D, F, T>::Init(const Fst<A> &fst) {
  // Mapper to an acceptor.
  ToFst to_fst(fst, ToMapper());

  // Determinizes acceptor.
  // This recursive call terminates since it passes the common divisor
  // to a private constructor.
  CacheOptions copts(GetCacheGc(), GetCacheLimit());
  DeterminizeFstOptions<ToArc, CommonDivisor> dopts(copts, delta_);
  // Uses acceptor-only constructor to avoid template recursion
  DeterminizeFst<ToArc> det_fsa(to_fst, 0, 0, dopts);

  // Mapper back to transducer.
  FactorWeightOptions<ToArc> fopts(CacheOptions(true, 0), delta_,
                                   kFactorFinalWeights,
                                   subsequential_label_,
                                   subsequential_label_);
  FactorWeightFst<ToArc, FactorIterator> factored_fst(det_fsa, fopts);
  from_fst_ = new FromFst(factored_fst, FromMapper(subsequential_label_));
}


// Specialization for DeterminizeFst.
template <class A>
class StateIterator< DeterminizeFst<A> >
    : public CacheStateIterator< DeterminizeFst<A> > {
 public:
  explicit StateIterator(const DeterminizeFst<A> &fst)
      : CacheStateIterator< DeterminizeFst<A> >(fst, fst.GetImpl()) {}
};


// Specialization for DeterminizeFst.
template <class A>
class ArcIterator< DeterminizeFst<A> >
    : public CacheArcIterator< DeterminizeFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const DeterminizeFst<A> &fst, StateId s)
      : CacheArcIterator< DeterminizeFst<A> >(fst.GetImpl(), s) {
    if (!fst.GetImpl()->HasArcs(s))
      fst.GetImpl()->Expand(s);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};


template <class A> inline
void DeterminizeFst<A>::InitStateIterator(StateIteratorData<A> *data) const
{
  data->base = new StateIterator< DeterminizeFst<A> >(*this);
}


// Useful aliases when using StdArc.
typedef DeterminizeFst<StdArc> StdDeterminizeFst;


template <class Arc>
struct DeterminizeOptions {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::Label Label;

  float delta;                // Quantization delta for subset weights.
  Weight weight_threshold;    // Pruning weight threshold.
  StateId state_threshold;    // Pruning state threshold.
  Label subsequential_label;  // Label used for residual final output
  // when producing subsequential transducers.

  explicit DeterminizeOptions(float d = kDelta, Weight w = Weight::Zero(),
                              StateId n = kNoStateId, Label l = 0)
      : delta(d), weight_threshold(w), state_threshold(n),
        subsequential_label(l) {}
};


// Determinizes a weighted transducer.  This version writes the
// determinized Fst to an output MutableFst.  The result will be an
// equivalent FST that has the property that no state has two
// transitions with the same input label.  For this algorithm, epsilon
// transitions are treated as regular symbols (cf. RmEpsilon).
//
// The transducer must be functional. The weights must be (weakly)
// left divisible (valid for TropicalWeight and LogWeight).
//
// Complexity:
// - Determinizable: exponential (polynomial in the size of the output)
// - Non-determinizable: does not terminate
//
// The determinizable automata include all unweighted and all acyclic input.
//
// References:
// - Mehryar Mohri, "Finite-State Transducers in Language and Speech
//   Processing". Computational Linguistics, 23:2, 1997.
template <class Arc>
void Determinize(const Fst<Arc> &ifst, MutableFst<Arc> *ofst,
             const DeterminizeOptions<Arc> &opts
                 = DeterminizeOptions<Arc>()) {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;

  DeterminizeFstOptions<Arc> nopts;
  nopts.delta = opts.delta;
  nopts.subsequential_label = opts.subsequential_label;

  nopts.gc_limit = 0;  // Cache only the last state for fastest copy.

  if (opts.weight_threshold != Weight::Zero() ||
      opts.state_threshold != kNoStateId) {
    if (ifst.Properties(kAcceptor, false)) {
      vector<Weight> idistance, odistance;
      ShortestDistance(ifst, &idistance, true);
      DeterminizeFst<Arc> dfst(ifst, &idistance, &odistance, nopts);
      PruneOptions< Arc, AnyArcFilter<Arc> > popts(opts.weight_threshold,
                                                   opts.state_threshold,
                                                   AnyArcFilter<Arc>(),
                                                   &odistance);
      Prune(dfst, ofst, popts);
    } else {
      *ofst = DeterminizeFst<Arc>(ifst, nopts);
      Prune(ofst, opts.weight_threshold, opts.state_threshold);
    }
  } else {
    *ofst = DeterminizeFst<Arc>(ifst, nopts);
  }
}


}  // namespace fst

#endif  // FST_LIB_DETERMINIZE_H__
