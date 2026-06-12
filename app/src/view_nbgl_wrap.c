/*******************************************************************************
 *   (c) 2018 - 2026 Algorand Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "bolos_target.h"

#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)

#include "nbgl_use_case.h"

/*
 * Linker-level workaround for oversized review values losing the "More"
 * button on touchscreen devices (linked with -Wl,--wrap on the two review
 * use cases below; see app/Makefile).
 *
 * ledger-zxlib pre-paginates long values into chunks sized for worst-case
 * hex rendering (MAX_CHARS_PER_VALUE1_LINE in zxlib's view_internal.h) and
 * sets nbMaxLinesForValue = NB_MAX_LINES_IN_REVIEW on the tag/value lists it
 * passes to the SDK. Text that renders wider than hex (e.g. base64) makes a
 * chunk overflow the review page. Since ledger-secure-sdk commit ba81334f
 * ("Long address shall span across mutliple screens", cherry-picked to
 * API_LEVEL_26 as d29dcd86, shipped in v26.2.0), getNbTagValuesInPage()
 * clamps the value's line count to nbMaxLinesForValue *before* the
 * NB_MAX_LINES_IN_REVIEW overflow check, so the SDK no longer routes the
 * oversized chunk to a TAG_VALUE_DETAILS page with a "More" button: it
 * truncates at the page boundary with "..." and the characters between the
 * cut and the next chunk are never shown on any page.
 *
 * A non-zero nbMaxLinesForValue now means "clamp this list, no details
 * page": it is how the SDK marks its own pre-chunked address lists. Ledger's
 * first-party apps (boilerplate, exchange, ethereum) all leave the field at
 * 0 and pass complete values, letting the SDK route anything oversized to
 * TAG_VALUE_DETAILS. Clearing the field here aligns zxlib's lists with that
 * reference pattern and restores the "More" button (the SDK still applies
 * its own per-page clamp at display time, so pages that fit render
 * unchanged). Only the exact value zxlib sets (NB_MAX_LINES_IN_REVIEW) is
 * cleared, so a list deliberately requesting a different clamp is left
 * untouched. On SDKs predating the change the field is not consulted during
 * pagination, making this a no-op. The cast below discards const added by
 * the SDK prototype; the pointee is zxlib's mutable static pairList.
 *
 * Only the use cases this app can reach are wrapped: REVIEW_TXN and
 * REVIEW_MSG both funnel into nbgl_useCaseReview /
 * nbgl_useCaseReviewBlindSigning. zxlib's other tag/value flows are
 * unreachable here (REVIEW_GENERIC -> nbgl_useCaseReviewLight is never used
 * by this app; REVIEW_ADDRESS already sets the field to 0). If a new review
 * type is introduced, wrap its use case too.
 *
 * Remove together with the planned migration off zxlib's NBGL view layer,
 * which will pass full values and let the SDK paginate (the reference-app
 * pattern), eliminating zxlib's chunk-budget assumptions entirely.
 */

void __real_nbgl_useCaseReview(nbgl_operationType_t operationType, const nbgl_contentTagValueList_t *tagValueList,
                               const nbgl_icon_details_t *icon, const char *reviewTitle, const char *reviewSubTitle,
                               const char *finishTitle, nbgl_choiceCallback_t choiceCallback);

void __real_nbgl_useCaseReviewBlindSigning(nbgl_operationType_t operationType,
                                           const nbgl_contentTagValueList_t *tagValueList,
                                           const nbgl_icon_details_t *icon, const char *reviewTitle,
                                           const char *reviewSubTitle, const char *finishTitle,
                                           const nbgl_tipBox_t *tipBox, nbgl_choiceCallback_t choiceCallback);

static void allow_value_overflow_detection(const nbgl_contentTagValueList_t *tagValueList)
{
    if (tagValueList != NULL && tagValueList->nbMaxLinesForValue == NB_MAX_LINES_IN_REVIEW) {
        ((nbgl_contentTagValueList_t *)tagValueList)->nbMaxLinesForValue = 0;
    }
}

void __wrap_nbgl_useCaseReview(nbgl_operationType_t operationType, const nbgl_contentTagValueList_t *tagValueList,
                               const nbgl_icon_details_t *icon, const char *reviewTitle, const char *reviewSubTitle,
                               const char *finishTitle, nbgl_choiceCallback_t choiceCallback)
{
    allow_value_overflow_detection(tagValueList);
    __real_nbgl_useCaseReview(operationType, tagValueList, icon, reviewTitle, reviewSubTitle, finishTitle,
                              choiceCallback);
}

void __wrap_nbgl_useCaseReviewBlindSigning(nbgl_operationType_t operationType,
                                           const nbgl_contentTagValueList_t *tagValueList,
                                           const nbgl_icon_details_t *icon, const char *reviewTitle,
                                           const char *reviewSubTitle, const char *finishTitle,
                                           const nbgl_tipBox_t *tipBox, nbgl_choiceCallback_t choiceCallback)
{
    allow_value_overflow_detection(tagValueList);
    __real_nbgl_useCaseReviewBlindSigning(operationType, tagValueList, icon, reviewTitle, reviewSubTitle, finishTitle,
                                          tipBox, choiceCallback);
}

#endif  // TARGET_STAX || TARGET_FLEX || TARGET_APEX_P
