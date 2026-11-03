@RestController
class MutationController {
    @RequiresStudyAccess(StudyPermission.DELETE_DATA)
    @PostMapping(path = ["/{study}/deletions/{op}/holds"])
    public fun recordHold() = Unit
}
