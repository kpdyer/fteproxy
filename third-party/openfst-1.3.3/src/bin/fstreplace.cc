
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
// Author: johans@google.com (Johan Schalkwyk)
// Modified: jpr@google.com (Jake Ratkiewicz) to use FstClass
//

#include <fst/script/replace.h>

DEFINE_bool(epsilon_on_replace, false, "Create an espilon arc when recursing");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::VectorFstClass;

  string usage = "Recursively replaces FST arcs with other FST(s).\n\n"
      "  Usage: ";
  usage += argv[0];
  usage += " root.fst rootlabel [rule1.fst label1 ...] [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 4) {
    ShowUsage();
    return 1;
  }

  string in_fname = argv[1];
  string out_fname = argc % 2 == 0 ? argv[argc - 1] : "";

  FstClass *ifst = FstClass::Read(in_fname);
  if (!ifst) return 1;

  typedef int64 Label;
  typedef pair<Label, const s::FstClass* > FstTuple;
  vector<FstTuple> fst_tuples;
  Label root = atoll(argv[2]);
  fst_tuples.push_back(make_pair(root, ifst));

  for (size_t i = 3; i < argc - 1; i += 2) {
    ifst = s::FstClass::Read(argv[i]);
    if (!ifst) return 1;
    Label lab = atoll(argv[i + 1]);
    fst_tuples.push_back(make_pair(lab, ifst));
  }

  VectorFstClass ofst(ifst->ArcType());
  Replace(fst_tuples, &ofst, root, FLAGS_epsilon_on_replace);

  ofst.Write(out_fname);

  return 0;
}
