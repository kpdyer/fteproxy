
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
// Author: jpr@google.com (Jake Ratkiewicz)

#ifndef FST_SCRIPT_REPLACE_H_
#define FST_SCRIPT_REPLACE_H_

#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/replace.h>

namespace fst {
namespace script {

typedef args::Package<const vector<pair<int64, const FstClass *> > &,
                      MutableFstClass *, const int64, bool> ReplaceArgs;

template<class Arc>
void Replace(ReplaceArgs *args) {
  // Now that we know the arc type, we construct a vector of
  // pair<real label, real fst> that the real Replace will use
  const vector<pair<int64, const FstClass *> >& untyped_tuples =
      args->arg1;

  vector<pair<typename Arc::Label, const Fst<Arc> *> > fst_tuples(
      untyped_tuples.size());

  for (unsigned i = 0; i < untyped_tuples.size(); ++i) {
    fst_tuples[i].first = untyped_tuples[i].first;  // convert label
    fst_tuples[i].second = untyped_tuples[i].second->GetFst<Arc>();
  }

  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();

  Replace(fst_tuples, ofst, args->arg3, args->arg4);
}

void Replace(const vector<pair<int64, const FstClass *> > &tuples,
             MutableFstClass *ofst, const int64 &root,
             bool epsilon_on_replace = false);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_REPLACE_H_
