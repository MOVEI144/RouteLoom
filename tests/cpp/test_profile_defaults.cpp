#include "routeloom/node.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_store.hpp"

#if ROUTELOOM_RESOURCE_PROFILE == ROUTELOOM_PROFILE_ENDPOINT
static_assert(routeloom::profile::kResourceProfile ==
              routeloom::profile::ResourceProfile::Endpoint);
static_assert(routeloom::kDedupCapacity == 32);
#elif ROUTELOOM_RESOURCE_PROFILE == ROUTELOOM_PROFILE_GATEWAY_SMALL
static_assert(routeloom::sdkv1::resume_quota(16).link == 0);
static_assert(routeloom::sdkv1::resume_quota(160).end == 128);
#endif

int main() { return 0; }
