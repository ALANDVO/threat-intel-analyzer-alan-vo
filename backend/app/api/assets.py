import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import require_role, verify_csrf
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import AssetEntity, UserEntity
from app.models.schemas import AssetCreate, AssetResponse, AssetUpdate, PaginatedResponse
from app.services.audit_service import audit_service

router = APIRouter(prefix='/assets', tags=['Assets'])

@router.get('', response_model=PaginatedResponse[AssetResponse])
def list_assets(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), environment: Optional[str] = None, criticality: Optional[str] = None, internet_exposed: Optional[bool] = None, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    q = db.query(AssetEntity)
    if environment: q = q.filter(AssetEntity.environment == environment.lower())
    if criticality: q = q.filter(AssetEntity.criticality == criticality.lower())
    if internet_exposed is not None: q = q.filter(AssetEntity.internet_exposed == internet_exposed)
    tot = q.count()
    items = q.order_by(AssetEntity.criticality.asc(), AssetEntity.name.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedResponse(items=[AssetResponse.model_validate(a) for a in items], total=tot, page=page, page_size=page_size, total_pages=math.ceil(tot / page_size) if tot > 0 else 1)

@router.get('/{asset_id}', response_model=AssetResponse)
def get_asset(asset_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    if not (a := db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()): raise HTTPException(status.HTTP_404_NOT_FOUND, f"Asset '{asset_id}' not found.")
    return AssetResponse.model_validate(a)

@router.post('', response_model=AssetResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))):
    a = AssetEntity(**payload.model_dump())
    db.add(a); db.flush()
    audit_service.log_action(db, current_user, 'asset.create', 'asset', a.id, {'name': a.name, 'component': a.component, 'version': a.version})
    db.commit()
    return AssetResponse.model_validate(a)

@router.put('/{asset_id}', response_model=AssetResponse, dependencies=[Depends(verify_csrf)])
def update_asset(asset_id: str, payload: AssetUpdate, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))):
    if not (a := db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()): raise HTTPException(status.HTTP_404_NOT_FOUND, f"Asset '{asset_id}' not found.")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items(): setattr(a, k, v)
    audit_service.log_action(db, current_user, 'asset.update', 'asset', a.id, data)
    db.commit()
    return AssetResponse.model_validate(a)

@router.delete('/{asset_id}', status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_asset(asset_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ADMIN))):
    if not (a := db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()): raise HTTPException(status.HTTP_404_NOT_FOUND, f"Asset '{asset_id}' not found.")
    db.delete(a); audit_service.log_action(db, current_user, 'asset.delete', 'asset', asset_id); db.commit()
