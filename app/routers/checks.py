from fastapi import APIRouter

router = APIRouter()


@router.get("/checks")
def list_checks():
    return []
