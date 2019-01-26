#ifdef VERSION_176
    #include "ksdk_176.inc"
#elif VERSION_455
#   include "ksdk_455.inc"
#elif VERSION_500
    #include "ksdk_500.inc"
#elif VERSION_505
    #include "ksdk_505.inc"
#else
    #error "Target firmware not yet supported."
#endif
